/**
 * Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef FILESYSTEM_DEFS_H_
#define FILESYSTEM_DEFS_H_

#include "plugin.h"

class Mount : public ParserPlugin{
public:
    ulong addr;
    ulong f_bsize;
    ulong f_blocks;
    ulong f_bfree;
    ulong f_bavail;
    std::string dev_name;
    std::string dir_name;
    std::string fs_type;
    ulong sb_addr;
    ulong fs_addr;
    ulong fs_info_addr;
    int mnt_flags;
    std::vector<std::shared_ptr<Mount>> childs;

    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    virtual void statfs(int width);
};

class F2fs: public Mount {
public:
    F2fs();
    void statfs(int width) override;
    void init_offset(void) override;
    void init_command(void) override;
};

class Ext4 : public Mount {
public:
    Ext4();
    void statfs(int width) override;
    void init_offset(void) override;
    void init_command(void) override;

private:
    long long percpu_counter_sum(ulong addr);
};

class FileSystem : public ParserPlugin {
private:
    std::vector<std::shared_ptr<Mount>> mount_list;
    std::unordered_map<size_t, std::shared_ptr<Mount>> sb_list;

    std::shared_ptr<Mount> parser_mount(ulong mount_addr);
    void print_mount_tree(std::vector<std::shared_ptr<Mount>>& mnt_list,int level);
    void print_partition_size(void);
    void parser_mount_tree(void);
    void parser_mount_tree(ulong mount_addr,std::vector<std::shared_ptr<Mount>>& mnt_list);

public:
    FileSystem();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(FileSystem)
};

#endif // FILESYSTEM_DEFS_H_
