// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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
