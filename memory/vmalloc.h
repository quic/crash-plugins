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

#ifndef VMALLOC_DEFS_H_
#define VMALLOC_DEFS_H_

#include "plugin.h"
#include "devicetree/devicetree.h"

struct vm_struct {
    ulong addr;
    ulong kaddr;
    ulong size;
    std::string flags;
    std::vector<ulong> page_list;
    int nr_pages;
    ulonglong phys_addr;
    std::string caller;
};

struct vmap_area {
    ulong addr;
    ulong va_start;
    ulong va_end;
    std::vector<std::shared_ptr<vm_struct>> vm_list;
};

struct vmalloc_info {
    std::string func;
    ulong virt_size;
    ulong page_cnt;
};

class Vmalloc : public PaserPlugin {
public:
    static const int VM_IOREMAP =0x00000001;
    static const int VM_ALLOC =0x00000002;
    static const int VM_MAP = 0x00000004;
    static const int VM_USERMAP =0x00000008;
    static const int VM_VPAGES =0x00000010;
    static const int VM_UNLIST =0x00000020;

    std::vector<std::shared_ptr<vmap_area>> area_list;
    Vmalloc();

    void parser_vmap_nodes();
    void parser_vmap_area(ulong addr);

    void cmd_main(void) override;
    void parser_vmap_area_list();
    void print_vmap_area_list();
    void print_vmap_area();
    void print_vm_struct();
    void print_summary_info();
    void print_summary_caller();
    void print_summary_type();
    void print_vm_info_caller(std::string func);
    void print_vm_info_type(std::string type);
    DEFINE_PLUGIN_INSTANCE(Vmalloc)
};


#endif // VMALLOC_DEFS_H_
