// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef PAGE_TABLE32_DEFS_H_
#define PAGE_TABLE32_DEFS_H_

// make sure that the header file is included only once
#pragma once

#include "plugin.h"

// from arm.c
#define PGDIR_SIZE() (4 * PAGESIZE())
#define PGDIR_OFFSET(X) (((ulong)(X)) & (PGDIR_SIZE() - 1))

class PageTable32 : public PaserPlugin {
public:
    PageTable32();
    void cmd_main(void) override;
    ulong* pmd_page_addr(ulong pmd);
    ulong get_pte(ulong task_addr, ulong page_vaddr);
};

#endif // PAGE_TABLE32_DEFS_H_