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

#ifndef SWAP_DEFS_H_
#define SWAP_DEFS_H_

#include "swapinfo.h"

class Swap : public Swapinfo {
public:
    Swap();
    Swap(std::shared_ptr<Zraminfo> zram);
    void cmd_main(void) override;
    void init_command();
    void print_swaps();
    void print_page_memory(std::string addr);
    DEFINE_PLUGIN_INSTANCE(Swap)
};

#endif // SWAP_DEFS_H_
