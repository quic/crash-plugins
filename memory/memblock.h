// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef MEMBLOCK_DEFS_H_
#define MEMBLOCK_DEFS_H_

#include "plugin.h"
#include "devicetree/devicetree.h"

enum memblock_flags {
  MEMBLOCK_NONE = 0,
  MEMBLOCK_HOTPLUG = 1,
  MEMBLOCK_MIRROR = 2,
  MEMBLOCK_NOMAP = 4,
};

struct memblock_region {
    ulong addr;
    physaddr_t base;
    physaddr_t size;
    enum memblock_flags flags;
};

struct memblock_type {
    ulong addr;
    unsigned long cnt;
    unsigned long max;
    unsigned long total_size;
    std::vector<std::shared_ptr<memblock_region>> regions;
    std::string name;
};

struct memblock {
    ulong addr;
    bool bottom_up;
    unsigned long current_limit;
    struct memblock_type memory;
    struct memblock_type reserved;
};

class Memblock : public PaserPlugin {
public:
    std::shared_ptr<memblock> block;
    Memblock();

    void cmd_main(void) override;
    void parser_memblock();
    void parser_memblock_type(ulong addr,memblock_type* type);
    std::vector<std::shared_ptr<memblock_region>> parser_memblock_region(ulong addr,int cnt);
    void print_memblock();
    void print_memblock_type(memblock_type* type);
    DEFINE_PLUGIN_INSTANCE(Memblock)
};


#endif // MEMBLOCK_DEFS_H_
