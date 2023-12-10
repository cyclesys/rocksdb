const std = @import("std");

pub fn build(b: *std.Build) !void {
    const root_dir = comptime rootDir();
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zstd_dep = b.dependency("zstd", .{
        .target = target,
        .optimize = optimize,
    });

    const lib = std.Build.Step.Compile.create(b, .{
        .name = "rocksdb",
        .kind = .lib,
        .linkage = .static,
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibCpp();
    lib.linkLibrary(zstd_dep.artifact("zstd"));

    const flags: []const []const u8 = switch (lib.target_info.target.os.tag) {
        .windows => base_flags ++ x86_64_flags ++ windows_flags,
        .macos => base_flags ++ x86_64_flags ++ posix_flags ++ macos_flags,
        .linux => base_flags ++ x86_64_flags ++ posix_flags ++ linux_flags,
        else => base_flags ++ x86_64_flags ++ posix_flags,
    };

    lib.addCSourceFiles(.{
        .files = &main_sources,
        .flags = flags,
    });

    const build_version_step = try genBuildVersionFile(b);
    const build_version_file = build_version_step.files.items[0];
    const build_version_file_path = build_version_file.getPath();
    lib.addCSourceFile(.{
        .file = build_version_file_path,
        .flags = flags,
    });

    switch (lib.target_info.target.os.tag) {
        .windows => {
            lib.linkSystemLibrary2("shlwapi", .{ .needed = true });
            lib.linkSystemLibrary2("rpcrt4", .{ .needed = true });
            lib.addCSourceFiles(.{
                .files = &windows_sources,
                .flags = flags,
            });
        },
        else => {
            lib.addCSourceFiles(.{
                .files = &posix_sources,
                .flags = flags,
            });
        },
    }

    lib.installHeadersDirectory(root_dir ++ "/include/rocksdb", "rocksdb");
    b.installArtifact(lib);
}

fn genBuildVersionFile(b: *std.Build) !*std.Build.Step.WriteFile {
    const root_dir = comptime rootDir();
    const file = try std.fs.openFileAbsolute(root_dir ++ "/util/build_version.cc.in", .{});
    defer file.close();

    const src = try file.readToEndAlloc(b.allocator, 1_000_000);
    defer b.allocator.free(src);

    const Placeholders = enum {
        git_sha,
        git_tag,
        git_mod,
        git_date,
        build_date,
        plugin_builtins,
        plugin_externs,
    };
    const placeholders = std.ComptimeStringMap(Placeholders, .{
        .{ "@GIT_SHA@", Placeholders.git_sha },
        .{ "@GIT_TAG@", Placeholders.git_tag },
        .{ "@GIT_MOD@", Placeholders.git_mod },
        .{ "@GIT_DATE@", Placeholders.git_date },
        .{ "@BUILD_DATE@", Placeholders.build_date },
        .{ "@ROCKSDB_PLUGIN_BUILTINS@", Placeholders.plugin_builtins },
        .{ "@ROCKSDB_PLUGIN_EXTERNS@", Placeholders.plugin_externs },
    });

    var dest = std.ArrayList(u8).init(b.allocator);
    defer dest.deinit();

    var start: ?usize = null;
    for (src, 0..) |byte, i| {
        if (byte == '@') {
            if (start == null) {
                start = i;
                continue;
            }

            const end = i + 1;
            const bytes = src[start.?..end];
            start = null;

            const tag = placeholders.get(bytes) orelse {
                try dest.appendSlice(bytes);
                continue;
            };
            switch (tag) {
                .git_sha => {
                    const git_sha = b.exec(&.{ "git", "rev-parse", "HEAD" });
                    defer b.allocator.free(git_sha);

                    // truncate the newline char
                    const sha_bytes = git_sha[0 .. git_sha.len - 1];
                    try dest.appendSlice(sha_bytes);
                },
                .git_tag => {
                    // this should be kept up-to-date with the latest version tag
                    const git_tag = "v8.8.1";
                    try dest.appendSlice(git_tag);
                },
                .git_mod => {
                    // this is always set to 0 so that the git_date is used by build_version.cc
                    const git_mod = "0";
                    try dest.appendSlice(git_mod);
                },
                .git_date => {
                    const git_date = b.exec(&.{ "git", "log", "-1", "--date=format:\"%Y-%m-%d %T\"", "--format=\"%ad\"" });
                    defer b.allocator.free(git_date);

                    // truncate the quote and newline chars
                    const date_bytes = git_date[2 .. git_date.len - 3];
                    try dest.appendSlice(date_bytes);
                },
                .build_date, .plugin_builtins, .plugin_externs => {
                    // These are left-out
                },
            }
        } else if (start == null) {
            try dest.append(byte);
        }
    }
    if (start) |s| {
        try dest.appendSlice(src[s..]);
    }

    return b.addWriteFile("build_version.cc", dest.items);
}

const base_flags: []const []const u8 = &[_][]const u8{
    "-std=c++17",
    "-O3",
    "-I" ++ rootDir(),
    "-I" ++ rootDir() ++ "/include",
    "-W",
    "-Wextra",
    "-Wall",
    "-Wshift-sign-overflow",
    "-Wambiguous-reversed-operator",
    "-fno-elide-constructors",
    "-Wsign-compare",
    "-Wshadow",
    "-Woverloaded-virtual",
    "-Wnon-virtual-dtor",
    "-Wno-missing-field-initializers",
    "-Wno-strict-aliasing",
    "-Wno-invalid-offsetof",
    "-momit-leaf-frame-pointer",
    "-march=haswell",
    "-DZSTD",
};

const posix_flags: []const []const u8 = &[_][]const u8{
    "-pthread",
    "-DROCKSDB_PLATFORM_POSIX",
    "-DROCKSDB_LIB_IO_POSIX",
};

const windows_flags: []const []const u8 = &[_][]const u8{
    "-Wno-format",
    "-D_POSIX_C_SOURCE=1",
    "-DWIN32",
    "-DOS_WIN",
    "-D_MBCS",
    "-DWIN64",
    "-DNOMINMAX",
};

const macos_flags: []const []const u8 = &[_][]const u8{
    "-DOS_MACOSX",
};

const linux_flags: []const []const u8 = &[_][]const u8{
    "-DOS_LINUX",
};

const x86_64_flags: []const []const u8 = &[_][]const u8{
    "-Wstrict-prototypes",
};

const main_sources = absolutePaths([_][]const u8{
    "cache/cache.cc",
    "cache/cache_entry_roles.cc",
    "cache/cache_key.cc",
    "cache/cache_helpers.cc",
    "cache/cache_reservation_manager.cc",
    "cache/charged_cache.cc",
    "cache/clock_cache.cc",
    "cache/compressed_secondary_cache.cc",
    "cache/lru_cache.cc",
    "cache/secondary_cache.cc",
    "cache/secondary_cache_adapter.cc",
    "cache/sharded_cache.cc",
    "cache/tiered_secondary_cache.cc",

    "db/arena_wrapped_db_iter.cc",
    "db/builder.cc",
    "db/c.cc",
    "db/column_family.cc",
    "db/convenience.cc",
    "db/db_filesnapshot.cc",
    "db/db_info_dumper.cc",
    "db/db_iter.cc",
    "db/dbformat.cc",
    "db/error_handler.cc",
    "db/event_helpers.cc",
    "db/experimental.cc",
    "db/external_sst_file_ingestion_job.cc",
    "db/file_indexer.cc",
    "db/flush_job.cc",
    "db/flush_scheduler.cc",
    "db/forward_iterator.cc",
    "db/import_column_family_job.cc",
    "db/internal_stats.cc",
    "db/logs_with_prep_tracker.cc",
    "db/log_reader.cc",
    "db/log_writer.cc",
    "db/malloc_stats.cc",
    "db/memtable.cc",
    "db/memtable_list.cc",
    "db/merge_helper.cc",
    "db/merge_operator.cc",
    "db/output_validator.cc",
    "db/periodic_task_scheduler.cc",
    "db/range_del_aggregator.cc",
    "db/range_tombstone_fragmenter.cc",
    "db/repair.cc",
    "db/seqno_to_time_mapping.cc",
    "db/snapshot_impl.cc",
    "db/table_cache.cc",
    "db/table_properties_collector.cc",
    "db/transaction_log_impl.cc",
    "db/trim_history_scheduler.cc",
    "db/version_builder.cc",
    "db/version_edit.cc",
    "db/version_edit_handler.cc",
    "db/version_set.cc",
    "db/wal_edit.cc",
    "db/wal_manager.cc",
    "db/write_batch.cc",
    "db/write_batch_base.cc",
    "db/write_controller.cc",
    "db/write_stall_stats.cc",
    "db/write_thread.cc",

    "db/blob/blob_contents.cc",
    "db/blob/blob_fetcher.cc",
    "db/blob/blob_file_addition.cc",
    "db/blob/blob_file_builder.cc",
    "db/blob/blob_file_cache.cc",
    "db/blob/blob_file_garbage.cc",
    "db/blob/blob_file_meta.cc",
    "db/blob/blob_file_reader.cc",
    "db/blob/blob_garbage_meter.cc",
    "db/blob/blob_log_format.cc",
    "db/blob/blob_log_sequential_reader.cc",
    "db/blob/blob_log_writer.cc",
    "db/blob/blob_source.cc",
    "db/blob/prefetch_buffer_collection.cc",

    "db/compaction/compaction.cc",
    "db/compaction/compaction_iterator.cc",
    "db/compaction/compaction_job.cc",
    "db/compaction/compaction_picker.cc",
    "db/compaction/compaction_picker_fifo.cc",
    "db/compaction/compaction_picker_level.cc",
    "db/compaction/compaction_picker_universal.cc",
    "db/compaction/compaction_service_job.cc",
    "db/compaction/compaction_state.cc",
    "db/compaction/compaction_outputs.cc",
    "db/compaction/sst_partitioner.cc",
    "db/compaction/subcompaction_state.cc",

    "db/db_impl/compacted_db_impl.cc",
    "db/db_impl/db_impl.cc",
    "db/db_impl/db_impl_compaction_flush.cc",
    "db/db_impl/db_impl_debug.cc",
    "db/db_impl/db_impl_experimental.cc",
    "db/db_impl/db_impl_files.cc",
    "db/db_impl/db_impl_open.cc",
    "db/db_impl/db_impl_readonly.cc",
    "db/db_impl/db_impl_secondary.cc",
    "db/db_impl/db_impl_write.cc",

    "db/wide/wide_column_serialization.cc",
    "db/wide/wide_columns.cc",
    "db/wide/wide_columns_helper.cc",

    "env/composite_env.cc",
    "env/env.cc",
    "env/env_chroot.cc",
    "env/env_encryption.cc",
    "env/file_system.cc",
    "env/file_system_tracer.cc",
    "env/fs_remap.cc",
    "env/mock_env.cc",
    "env/unique_id_gen.cc",

    "file/delete_scheduler.cc",
    "file/file_prefetch_buffer.cc",
    "file/file_util.cc",
    "file/filename.cc",
    "file/line_file_reader.cc",
    "file/random_access_file_reader.cc",
    "file/read_write_util.cc",
    "file/readahead_raf.cc",
    "file/sequence_file_reader.cc",
    "file/sst_file_manager_impl.cc",
    "file/writable_file_writer.cc",

    "logging/auto_roll_logger.cc",
    "logging/event_logger.cc",
    "logging/log_buffer.cc",

    "memory/arena.cc",
    "memory/concurrent_arena.cc",
    "memory/jemalloc_nodump_allocator.cc",
    "memory/memkind_kmem_allocator.cc",
    "memory/memory_allocator.cc",

    "memtable/alloc_tracker.cc",
    "memtable/hash_linklist_rep.cc",
    "memtable/hash_skiplist_rep.cc",
    "memtable/skiplistrep.cc",
    "memtable/vectorrep.cc",
    "memtable/write_buffer_manager.cc",

    "monitoring/histogram.cc",
    "monitoring/histogram_windowing.cc",
    "monitoring/in_memory_stats_history.cc",
    "monitoring/instrumented_mutex.cc",
    "monitoring/iostats_context.cc",
    "monitoring/perf_context.cc",
    "monitoring/perf_level.cc",
    "monitoring/persistent_stats_history.cc",
    "monitoring/statistics.cc",
    "monitoring/thread_status_impl.cc",
    "monitoring/thread_status_updater.cc",
    "monitoring/thread_status_updater_debug.cc",
    "monitoring/thread_status_util.cc",
    "monitoring/thread_status_util_debug.cc",

    "options/cf_options.cc",
    "options/configurable.cc",
    "options/customizable.cc",
    "options/db_options.cc",
    "options/options.cc",
    "options/options_helper.cc",
    "options/options_parser.cc",

    "port/mmap.cc",
    "port/stack_trace.cc",

    "table/block_fetcher.cc",
    "table/compaction_merging_iterator.cc",
    "table/format.cc",
    "table/get_context.cc",
    "table/iterator.cc",
    "table/merging_iterator.cc",
    "table/meta_blocks.cc",
    "table/persistent_cache_helper.cc",
    "table/sst_file_dumper.cc",
    "table/sst_file_reader.cc",
    "table/sst_file_writer.cc",
    "table/table_factory.cc",
    "table/table_properties.cc",
    "table/two_level_iterator.cc",
    "table/unique_id.cc",

    "table/adaptive/adaptive_table_factory.cc",

    "table/block_based/binary_search_index_reader.cc",
    "table/block_based/block.cc",
    "table/block_based/block_based_table_builder.cc",
    "table/block_based/block_based_table_factory.cc",
    "table/block_based/block_based_table_iterator.cc",
    "table/block_based/block_based_table_reader.cc",
    "table/block_based/block_builder.cc",
    "table/block_based/block_cache.cc",
    "table/block_based/block_prefetcher.cc",
    "table/block_based/block_prefix_index.cc",
    "table/block_based/data_block_hash_index.cc",
    "table/block_based/data_block_footer.cc",
    "table/block_based/filter_block_reader_common.cc",
    "table/block_based/filter_policy.cc",
    "table/block_based/flush_block_policy.cc",
    "table/block_based/full_filter_block.cc",
    "table/block_based/hash_index_reader.cc",
    "table/block_based/index_builder.cc",
    "table/block_based/index_reader_common.cc",
    "table/block_based/parsed_full_filter_block.cc",
    "table/block_based/partitioned_filter_block.cc",
    "table/block_based/partitioned_index_iterator.cc",
    "table/block_based/partitioned_index_reader.cc",
    "table/block_based/reader_common.cc",
    "table/block_based/uncompression_dict_reader.cc",

    "table/cuckoo/cuckoo_table_builder.cc",
    "table/cuckoo/cuckoo_table_factory.cc",
    "table/cuckoo/cuckoo_table_reader.cc",

    "table/plain/plain_table_bloom.cc",
    "table/plain/plain_table_builder.cc",
    "table/plain/plain_table_factory.cc",
    "table/plain/plain_table_index.cc",
    "table/plain/plain_table_key_coding.cc",
    "table/plain/plain_table_reader.cc",

    "test_util/sync_point.cc",
    "test_util/sync_point_impl.cc",
    "test_util/transaction_test_util.cc",

    "tools/dump/db_dump_tool.cc",

    "trace_replay/block_cache_tracer.cc",
    "trace_replay/io_tracer.cc",
    "trace_replay/trace_record_handler.cc",
    "trace_replay/trace_record_result.cc",
    "trace_replay/trace_record.cc",
    "trace_replay/trace_replay.cc",

    "util/async_file_reader.cc",
    "util/cleanable.cc",
    "util/coding.cc",
    "util/compaction_job_stats_impl.cc",
    "util/comparator.cc",
    "util/compression.cc",
    "util/compression_context_cache.cc",
    "util/concurrent_task_limiter_impl.cc",
    "util/crc32c.cc",
    "util/data_structure.cc",
    "util/dynamic_bloom.cc",
    "util/hash.cc",
    "util/murmurhash.cc",
    "util/random.cc",
    "util/rate_limiter.cc",
    "util/ribbon_config.cc",
    "util/slice.cc",
    "util/file_checksum_helper.cc",
    "util/status.cc",
    "util/stderr_logger.cc",
    "util/string_util.cc",
    "util/thread_local.cc",
    "util/threadpool_imp.cc",
    "util/udt_util.cc",
    "util/write_batch_util.cc",
    "util/xxhash.cc",

    "utilities/cache_dump_load.cc",
    "utilities/cache_dump_load_impl.cc",
    "utilities/compaction_filters.cc",
    "utilities/counted_fs.cc",
    "utilities/debug.cc",
    "utilities/env_mirror.cc",
    "utilities/env_timed.cc",
    "utilities/fault_injection_env.cc",
    "utilities/fault_injection_fs.cc",
    "utilities/fault_injection_secondary_cache.cc",
    "utilities/merge_operators.cc",
    "utilities/object_registry.cc",
    "utilities/wal_filter.cc",

    "utilities/agg_merge/agg_merge.cc",

    "utilities/backup/backup_engine.cc",

    "utilities/blob_db/blob_compaction_filter.cc",
    "utilities/blob_db/blob_db.cc",
    "utilities/blob_db/blob_db_impl.cc",
    "utilities/blob_db/blob_db_impl_filesnapshot.cc",
    "utilities/blob_db/blob_file.cc",

    "utilities/cassandra/cassandra_compaction_filter.cc",
    "utilities/cassandra/format.cc",
    "utilities/cassandra/merge_operator.cc",

    "utilities/checkpoint/checkpoint_impl.cc",

    "utilities/compaction_filters/remove_emptyvalue_compactionfilter.cc",

    "utilities/convenience/info_log_finder.cc",

    "utilities/leveldb_options/leveldb_options.cc",

    "utilities/memory/memory_util.cc",

    "utilities/merge_operators/bytesxor.cc",
    "utilities/merge_operators/max.cc",
    "utilities/merge_operators/put.cc",
    "utilities/merge_operators/sortlist.cc",
    "utilities/merge_operators/string_append/stringappend.cc",
    "utilities/merge_operators/string_append/stringappend2.cc",
    "utilities/merge_operators/uint64add.cc",

    "utilities/option_change_migration/option_change_migration.cc",

    "utilities/options/options_util.cc",

    "utilities/persistent_cache/block_cache_tier.cc",
    "utilities/persistent_cache/block_cache_tier_file.cc",
    "utilities/persistent_cache/block_cache_tier_metadata.cc",
    "utilities/persistent_cache/persistent_cache_tier.cc",
    "utilities/persistent_cache/volatile_tier_impl.cc",

    "utilities/simulator_cache/cache_simulator.cc",
    "utilities/simulator_cache/sim_cache.cc",

    "utilities/table_properties_collectors/compact_on_deletion_collector.cc",

    "utilities/trace/file_trace_reader_writer.cc",
    "utilities/trace/replayer_impl.cc",

    "utilities/transactions/optimistic_transaction.cc",
    "utilities/transactions/optimistic_transaction_db_impl.cc",
    "utilities/transactions/pessimistic_transaction.cc",
    "utilities/transactions/pessimistic_transaction_db.cc",
    "utilities/transactions/snapshot_checker.cc",
    "utilities/transactions/transaction_base.cc",
    "utilities/transactions/transaction_db_mutex_impl.cc",
    "utilities/transactions/transaction_util.cc",
    "utilities/transactions/write_prepared_txn.cc",
    "utilities/transactions/write_prepared_txn_db.cc",
    "utilities/transactions/write_unprepared_txn.cc",
    "utilities/transactions/write_unprepared_txn_db.cc",
    "utilities/transactions/lock/lock_manager.cc",
    "utilities/transactions/lock/point/point_lock_tracker.cc",
    "utilities/transactions/lock/point/point_lock_manager.cc",

    "utilities/ttl/db_ttl_impl.cc",

    "utilities/write_batch_with_index/write_batch_with_index.cc",
    "utilities/write_batch_with_index/write_batch_with_index_internal.cc",
});

const windows_sources = absolutePaths([_][]const u8{
    "port/win/env_default.cc",
    "port/win/env_win.cc",
    "port/win/io_win.cc",
    "port/win/port_win.cc",
    "port/win/win_logger.cc",
    "port/win/win_thread.cc",
});

const posix_sources = absolutePaths([_][]const u8{
    "env/env_posix.cc",
    "env/fs_posix.cc",
    "env/io_posix.cc",

    "port/port_posix.cc",
});

const arm64_sources = absolutePaths([_][]const u8{
    "util/crc32c_arm64.cc",
});

fn absolutePaths(comptime paths: anytype) [paths.len][]const u8 {
    comptime {
        const root_dir = rootDir();
        var out_paths: [paths.len][]const u8 = undefined;
        for (paths, 0..) |path, i| {
            out_paths[i] = root_dir ++ "/" ++ path;
        }
        return out_paths;
    }
}

fn rootDir() []const u8 {
    comptime {
        return std.fs.path.dirname(@src().file) orelse ".";
    }
}
