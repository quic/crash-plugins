// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef PROCRANK_DEFS_H_
#define PROCRANK_DEFS_H_
#include "plugin.h"

#ifdef ARM64
#include "pagetable/arm/pagetable64.h"
#else
#include "pagetable/arm/pagetable32.h"
#endif

struct procrank{
    ulong vss;
    ulong rss;
    ulong pss;
    ulong uss;
    ulong swap;
    ulong pid;
    // char comm[TASK_COMM_LEN+1];
    std::string cmdline;
};

#ifdef ARM64
class Procrank : public PageTable64 {
#else
class Procrank : public PageTable32 {
#endif
public:
    Procrank();
    void cmd_main(void) override;
    void parser_process_memory();
    std::shared_ptr<procrank> parser_vma(ulong& vma_addr, ulong& task_addr);
    DEFINE_PLUGIN_INSTANCE(Procrank)

private:
    std::vector<std::shared_ptr<procrank>> procrank_list;
    const ulong page_mask = ~((ulong)(PAGESIZE() - 1));
};
#endif // PROCRANK_DEFS_H_
