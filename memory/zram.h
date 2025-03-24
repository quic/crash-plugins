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

#ifndef ZRAM_DEFS_H_
#define ZRAM_DEFS_H_

#include "memory/zraminfo.h"

class Zram : public Zraminfo {
private:
    static const int PRINT_SIZE_CLASS = 0x0001;
    static const int PRINT_ZSPAGE = 0x0002;
    static const int PRINT_PAGE = 0x0004;
public:
    Zram();
    void cmd_main(void) override;
    void print_zrams();
    void print_zram_full_info(std::string zram_addr);
    void print_mem_pool(std::string zram_addr);
    void print_zram_stat(std::string zram_addr);
    void print_pages(std::string zram_addr);
    void print_zspages(std::string zram_addr);
    void print_objs(std::string addr);
    void print_size_class_obj(std::shared_ptr<size_class> class_ptr);
    void print_zspage_obj(std::shared_ptr<zpage> zspage_ptr);
    void print_page_obj(std::shared_ptr<pageinfo> page_ptr);
    DEFINE_PLUGIN_INSTANCE(Zram)
};

#endif // ZRAM_DEFS_H_
