// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "pagetable32.h"

PageTable32::PageTable32(){
    // field_init(vm_area_struct,vm_start);
    // struct_init(vm_area_struct);
}

void PageTable32::cmd_main(void) {

}

ulong* PageTable32::pmd_page_addr(ulong pmd){
    ulong ptr;
    if (machdep->flags & PGTABLE_V2) {
        ptr = PAGEBASE(pmd);
    } else {
        ptr = pmd & ~(PTRS_PER_PTE * sizeof(void *) - 1);
        ptr += PTRS_PER_PTE * sizeof(void *);
    }
    return (ulong *)ptr;
}

// from arm_vtop in arm.c
ulong PageTable32::get_pte(ulong task_addr, ulong page_vaddr){
    char buf[BUFSIZE];
    int verbose = 0;
    ulong *pgd;
    ulong *page_dir;
    ulong *page_middle;
    ulong *page_table;
    ulong pgd_pte;
    ulong pmd_pte;
    ulong pte;
    struct task_context *tc;
    tc = task_to_context(task_addr);
    /*
     * Before idmap_pgd was introduced with upstream commit 2c8951ab0c
     * (ARM: idmap: use idmap_pgd when setting up mm for reboot), the
     * panic task pgd was overwritten by soft reboot code, so we can't do
     * any vtop translations.
     */
    if (!(machdep->flags & IDMAP_PGD) && tc->task == tt->panic_task)
        error(FATAL, TO_CONST_STRING("panic task pgd is trashed by soft reboot code\n"));

    if (is_kernel_thread(tc->task) && IS_KVADDR(page_vaddr)) {
        ulong active_mm = read_structure_field(tc->task,"task_struct","active_mm");
        if (!active_mm)
            error(FATAL, TO_CONST_STRING("no active_mm for this kernel thread\n"));

        pgd = ULONG_PTR(read_structure_field(active_mm,"mm_struct","pgd"));
    } else {
        ulong mm = task_mm(tc->task, TRUE);
        if (mm){
            pgd = ULONG_PTR(tt->mm_struct + field_offset(mm_struct, pgd));
        }else{
            pgd = ULONG_PTR(read_structure_field(tc->mm_struct,"mm_struct","pgd"));
        }
    }
    /*
     * Page tables in ARM Linux
     *
     * In hardware PGD is 16k (having 4096 pointers to PTE) and PTE is 1k
     * (containing 256 translations).
     *
     * Linux, however, wants to have PTEs as page sized entities. This means
     * that in ARM Linux we have following setup (see also
     * arch/arm/include/asm/pgtable.h)
     *
     * Before 2.6.38
     *
     *     PGD                   PTE
     * +---------+
     * |         | 0  ---->  +------------+
     * +- - - - -+           | h/w pt 0   |
     * |         | 4  ---->  +------------+ +1024
     * +- - - - -+           | h/w pt 1   |
     * .         .           +------------+ +2048
     * .         .           | Linux pt 0 |
     * .         .           +------------+ +3072
     * |         | 4095      | Linux pt 1 |
     * +---------+           +------------+ +4096
     *
     * Starting from 2.6.38
     *
     *     PGD                   PTE
     * +---------+
     * |         | 0  ---->  +------------+
     * +- - - - -+           | Linux pt 0 |
     * |         | 4  ---->  +------------+ +1024
     * +- - - - -+           | Linux pt 1 |
     * .         .           +------------+ +2048
     * .         .           | h/w pt 0   |
     * .         .           +------------+ +3072
     * |         | 4095      | h/w pt 1   |
     * +---------+           +------------+ +4096
     *
     * So in Linux implementation we have two hardware pointers to second
     * level page tables. Depending on the kernel version, the "Linux" page
     * tables either follow or precede the hardware tables.
     *
     * Linux PT entries contain bits that are not supported on hardware, for
     * example "young" and "dirty" flags.
     *
     * Our translation scheme only uses Linux PTEs here.
     */
    if (verbose){
        fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);
    }
    /*
     * pgd_offset(pgd, vaddr)
     */
    page_dir = pgd + PGD_OFFSET(page_vaddr) * 2;
    /* The unity-mapped region is mapped using 1MB pages,
     * hence 1-level translation if bit 20 is set; if we
     * are 1MB apart physically, we move the page_dir in
     * case bit 20 is set.
     */
    if (((page_vaddr) >> (20)) & 1){
        page_dir = page_dir + 1;
    }
    cfill_pgd(PAGEBASE(pgd), KVADDR, PGDIR_SIZE());
    pgd_pte = ULONG(machdep->pgd + PGDIR_OFFSET(page_dir));
    if (verbose){
        fprintf(fp, "  PGD: %s => %lx\n",mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,MKSTR((ulong)page_dir)), pgd_pte);
    }
    if (!pgd_pte){
        return 0;
    }
    /*
     * pmd_offset(pgd, vaddr)
     *
     * Here PMD is folded into a PGD.
     */
    pmd_pte = pgd_pte;
    page_middle = page_dir;
    if (verbose){
        fprintf(fp, "  PMD: %s => %lx\n",mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,MKSTR((ulong)page_middle)), pmd_pte);
    }
    /*
     * pte_offset_map(pmd, vaddr)
     */
    page_table = pmd_page_addr(pmd_pte) + PTE_OFFSET(page_vaddr);
    cfill_ptbl(PAGEBASE(page_table), PHYSADDR, PAGESIZE());
    pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));
    if (verbose) {
        fprintf(fp, "  PTE: %s => %lx\n\n",mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,MKSTR((ulong)page_table)), pte);
    }
    return pte;
}