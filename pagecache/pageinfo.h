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

#ifndef PAGE_INFO_DEFS_H_
#define PAGE_INFO_DEFS_H_

#include "plugin.h"

struct FileCache {
    ulong inode;
    std::string name;
    ulong i_mapping;
    ulong nrpages;
};

class Pageinfo : public ParserPlugin {
private:
    std::vector<std::shared_ptr<FileCache>> cache_list;
    
public:
    Pageinfo();
    bool page_buddy(ulong page_addr);
    int page_count(ulong page_addr);
    void parser_file_pages();
    void print_file_pages();
    void init_offset();
    void cmd_main(void) override;
    void print_anon_pages();
    DEFINE_PLUGIN_INSTANCE(Pageinfo)
};

#endif // PAGE_INFO_DEFS_H_
