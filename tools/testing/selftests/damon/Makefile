# SPDX-License-Identifier: GPL-2.0
# Makefile for damon selftests

TEST_GEN_FILES += huge_count_read_write
TEST_GEN_FILES += access_memory

TEST_FILES = _chk_dependency.sh _debugfs_common.sh _damon_sysfs.py
TEST_PROGS = debugfs_attrs.sh debugfs_schemes.sh debugfs_target_ids.sh
TEST_PROGS += debugfs_empty_targets.sh debugfs_huge_count_read_write.sh
TEST_PROGS += debugfs_duplicate_context_creation.sh
TEST_PROGS += debugfs_rm_non_contexts.sh
TEST_PROGS += sysfs.sh sysfs_update_removed_scheme_dir.sh
TEST_PROGS += sysfs_update_schemes_tried_regions_hang.py
TEST_PROGS += sysfs_update_schemes_tried_regions_wss_estimation.py
TEST_PROGS += reclaim.sh lru_sort.sh

include ../lib.mk
