// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef PAGE_TABLE64_DEFS_H_
#define PAGE_TABLE64_DEFS_H_

// make sure that the header file is included only once
#pragma once

#include "plugin.h"

// from arm64.c
#define PTE_ADDR_LOW   ((((1UL) << (48 - machdep->pageshift)) - 1) << machdep->pageshift)
#define PTE_ADDR_HIGH  ((0xfUL) << 12)
#define PTE_ADDR_HIGH_SHIFT 36
#define PTE_TO_PHYS(pteval)  (machdep->max_physmem_bits == 52 ? \
       (((pteval & PTE_ADDR_LOW) | ((pteval & PTE_ADDR_HIGH) << PTE_ADDR_HIGH_SHIFT))) : (pteval & PTE_ADDR_LOW))

class PageTable64 : public PaserPlugin {

public:
    PageTable64();
    void cmd_main(void) override;
    ulong get_pte(ulong task_addr, ulong page_vaddr);
};

#endif // PAGE_TABLE64_DEFS_H_