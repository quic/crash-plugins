// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "pagetable64.h"

PageTable64::PageTable64(){
    // field_init(vm_area_struct,vm_start);
    // struct_init(vm_area_struct);
}

void PageTable64::cmd_main(void) {

}

// VM_L3_4K arm64_vtop_3level_4k
ulong PageTable64::get_pte(ulong task_addr, ulong page_vaddr){
    int verbose = 0;
    ulong *pgd_base, *pgd_ptr, pgd_val;
    ulong *pmd_base, *pmd_ptr, pmd_val;
    ulong *pte_base, *pte_ptr, pte_val;
    struct task_context *tc;
    tc = task_to_context(task_addr);
    ulong user_pgd = read_structure_field(tc->mm_struct,"mm_struct","pgd");
    if (verbose){
        fprintf(fp, "PAGE DIRECTORY: %lx\n", user_pgd);
    }
    pgd_base = (ulong *)user_pgd;
    // FILL_PGD(pgd_base, KVADDR, PTRS_PER_PGD_L3_4K * sizeof(ulong));
    cfill_pgd((ulonglong)(uintptr_t)pgd_base, KVADDR, PTRS_PER_PGD_L3_4K * sizeof(ulong));
    pgd_ptr = pgd_base + (((page_vaddr) >> PGDIR_SHIFT_L3_4K) & (PTRS_PER_PGD_L3_4K - 1));
    pgd_val = ULONG(machdep->pgd + PAGEOFFSET(pgd_ptr));
    if (verbose){
        fprintf(fp, "   PGD: %lx => %lx\n", (ulong)pgd_ptr, pgd_val);
    }  
    if (!pgd_val){
        return 0;
    }
    pmd_base = (ulong *)PTOV(PTE_TO_PHYS(pgd_val));
    // FILL_PMD(pmd_base, KVADDR, PTRS_PER_PMD_L3_4K * sizeof(ulong));
    cfill_pmd((ulonglong)(uintptr_t)pmd_base, KVADDR, PTRS_PER_PMD_L3_4K * sizeof(ulong));
    pmd_ptr = pmd_base + (((page_vaddr) >> PMD_SHIFT_L3_4K) & (PTRS_PER_PMD_L3_4K - 1));
    pmd_val = ULONG(machdep->pmd + PAGEOFFSET(pmd_ptr));
    if (verbose){
        fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd_ptr, pmd_val);
    }
    if (!pmd_val){
        return 0;
    }
    pte_base = (ulong *)PTOV(PTE_TO_PHYS(pmd_val));
    // FILL_PTBL(pte_base, KVADDR, PTRS_PER_PTE_L3_4K * sizeof(ulong));
    cfill_ptbl((ulonglong)(uintptr_t)pte_base, KVADDR, PTRS_PER_PTE_L3_4K * sizeof(ulong));
    pte_ptr = pte_base + (((page_vaddr) >> machdep->pageshift) & (PTRS_PER_PTE_L3_4K - 1));
    pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
    if (verbose){
        fprintf(fp, "   PTE: %lx => %lx\n", (ulong)pte_ptr, pte_val);
    }
    if (!pte_val){
        return 0;
    }
    return pte_val;
}