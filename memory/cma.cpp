// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "cma.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Cma)
#endif

void Cma::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "au:f:")) != EOF) {
        switch(c) {
            case 'a':
                print_cma_areas();
                break;
            case 'u':
                cppString.assign(optarg);
                print_cma_page_status(cppString,true);
                break;
            case 'f':
                cppString.assign(optarg);
                print_cma_page_status(cppString,false);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Cma::Cma(){
    field_init(cma,base_pfn);
    field_init(cma,count);
    field_init(cma,bitmap);
    field_init(cma,order_per_bit);
    field_init(cma,name);
    struct_init(cma);
    cmd_name = "cma";
    help_str_list={
        "cma",                            /* command name */
        "dump cma information",        /* short description */
        "-a \n"
            "  cma -u <cma name>\n"
            "  cma -f <cma name>\n"
            "  This command dumps the cma info.",
        "\n",
        "EXAMPLES",
        "  Display cma memory info:",
        "    %s> cma -a",
        "    ==============================================================================================================",
        "    [1]mem_dump_region            cma:0xffffffde315f35a8 PFN:0xbf800~0xc0000       size:8.00Mb     used:0b         order:0",
        "    [2]user_contig_region         cma:0xffffffde315f3668 PFN:0xbe800~0xbf800       size:16.00Mb    used:0b         order:0",
        "    [3]adsp_region                cma:0xffffffde315f3728 PFN:0xbe000~0xbe800       size:8.00Mb     used:2.20Mb     order:0",
        "    [4]linux,cma                  cma:0xffffffde315f37e8 PFN:0xbc000~0xbe000       size:32.00Mb    used:12.38Mb    order:0",
        "    ==============================================================================================================",
        "    Total:264.00Mb allocated:15.77Mb",
        "\n",
        "  Display the allocted pages of specified cma region by cma name:",
        "    %s> cma -u adsp_region",
        "    ========================================================================",
        "    name           : adsp_region",
        "    base_pfn       : 0xbe000",
        "    end_pfn        : 0xbe800",
        "    count          : 2048",
        "    size           : 0x2000",
        "    bitmap         : 0xffffff8006986900 ~ 0xffffff8006986a00",
        "    ========================================================================",
        "    [1]PFN:0xbe000 paddr:0xbe000000 page:0xfffffffe01f80000 allocted",
        "    [2]PFN:0xbe001 paddr:0xbe001000 page:0xfffffffe01f80040 allocted",
        "    [3]PFN:0xbe002 paddr:0xbe002000 page:0xfffffffe01f80080 allocted",
        "    [4]PFN:0xbe003 paddr:0xbe003000 page:0xfffffffe01f800c0 allocted",
        "\n",
        "  Display the free pages of specified cma region by cma name:",
        "    %s> cma -f adsp_region",
        "    ========================================================================",
        "    name           : adsp_region",
        "    base_pfn       : 0xbe000",
        "    end_pfn        : 0xbe800",
        "    count          : 2048",
        "    size           : 0x2000",
        "    bitmap         : 0xffffff8006986900 ~ 0xffffff8006986a00",
        "    ========================================================================",
        "    [1]PFN:0xbe032 paddr:0xbe032000 page:0xfffffffe01f80c80 free",
        "    [2]PFN:0xbe033 paddr:0xbe033000 page:0xfffffffe01f80cc0 free",
        "    [3]PFN:0xbe034 paddr:0xbe034000 page:0xfffffffe01f80d00 free",
        "\n",
    };
    initialize();
    parser_cma_areas();
}

void Cma::parser_cma_areas(){
    if (!csymbol_exists("cma_areas")){
        LOGE("cma_areas doesn't exist in this kernel!\n");
        return;
    }
    ulong cma_areas_addr = csymbol_value("cma_areas");
    if (!cma_areas_addr) return;
    ulong cma_area_count = read_ulong(csymbol_value("cma_area_count"),"cma_area_count");
    for (int i = 0; i < cma_area_count; ++i) {
        ulong cma_addr = cma_areas_addr + i * struct_size(cma);
        void *cma_buf = read_struct(cma_addr,"cma");
        if(cma_buf == nullptr) return;
        std::shared_ptr<cma_mem> cma_ptr = std::make_shared<cma_mem>();
        cma_ptr->addr = cma_addr;
        cma_ptr->base_pfn = ULONG(cma_buf + field_offset(cma,base_pfn));
        cma_ptr->count = ULONG(cma_buf + field_offset(cma,count));
        cma_ptr->bitmap = ULONG(cma_buf + field_offset(cma,bitmap));
        cma_ptr->order_per_bit = UINT(cma_buf + field_offset(cma,order_per_bit));
        // read cma name
        if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
            char cma_name[64];
            memcpy(&cma_name,cma_buf + field_offset(cma,name),64);
            cma_ptr->name = cma_name;
        }else{
            ulong name_addr = ULONG(cma_buf + field_offset(cma,name));
            cma_ptr->name = read_cstring(name_addr,64, "cma_name");
        }
        cma_ptr->allocated_size = get_cma_used_size(cma_ptr);
        FREEBUF(cma_buf);
        mem_list.push_back(cma_ptr);
    }
}

void Cma::print_cma_areas(){
    char buf_index[BUFSIZE];
    char buf_name[BUFSIZE];
    char buf_addr[BUFSIZE];
    char buf_pfn[BUFSIZE];
    char buf_size[BUFSIZE];
    char buf_used[BUFSIZE];
    char buf_order[BUFSIZE];
    ulong totalcma_pages = 0;
    ulong total_use = 0;
    fprintf(fp, "==============================================================================================================\n");
    int index = 1;
    size_t max_len = 0;
    for (const auto& cma : mem_list) {
        max_len = std::max(max_len,cma->name.size());
    }
    for (const auto& cma : mem_list) {
        totalcma_pages += cma->count;
        total_use += cma->allocated_size;

        sprintf(buf_index, "[%d]",index);
        sprintf(buf_addr, "cma:0x%lx",cma->addr);
        sprintf(buf_pfn, "range:[0x%lx~0x%lx]",cma->base_pfn << 12,(cma->base_pfn + cma->count) << 12);
        convert_size(cma->count * page_size,buf_size);
        convert_size(cma->allocated_size,buf_used);
        fprintf(fp, "%s%s %s %s size:%s used:%s order:%s\n",
            mkstring(buf_index, 4, LJUST,buf_index),
            mkstring(buf_name, max_len + 1, LJUST, cma->name.c_str()),
            mkstring(buf_addr, 20, LJUST, buf_addr),
            mkstring(buf_pfn,20, LJUST, buf_pfn),
            mkstring(buf_size, 10, LJUST, buf_size),
            mkstring(buf_used, 7, LJUST, buf_used),
            mkstring(buf_order, 5, LJUST|INT_DEC, (char *)(unsigned long)cma->order_per_bit));
        index += 1;
    }
    fprintf(fp, "==============================================================================================================\n");
    convert_size(totalcma_pages * page_size,buf_size);
    fprintf(fp, "Total:%s ",buf_size);
    convert_size(total_use,buf_size);
    fprintf(fp, "allocated:%s\n",buf_size);
}

int Cma::get_cma_used_size(std::shared_ptr<cma_mem> cma){
    // calc how many byte of bitmap
    int nr_byte = (cma->count >> cma->order_per_bit) / 8;
    int per_bit_size = (1U << cma->order_per_bit) * page_size;
    int used_count = 0;
    ulong bitmap_addr = cma->bitmap;
    for (int i = 0; i < nr_byte; ++i) {
        unsigned char bitmap_data = read_byte(bitmap_addr,"cma bitmap");
        std::bitset<8> bits(bitmap_data);
        int nr_bit = bits.count();
        // fprintf(fp, "bitmap_addr:0x%lx bitmap:%x, nr_bit:%d\n",bitmap_addr, bitmap_data, nr_bit);
        used_count += nr_bit;
        bitmap_addr += 1;
    }
    return (used_count * per_bit_size);
}

void Cma::print_cma_page_status(std::string name,bool alloc){
    char buf[BUFSIZE];
    for (const auto& cma : mem_list) {
        if (cma->name.find(name) != std::string::npos) {
            fprintf(fp, "\n========================================================================\n");
            sprintf(buf, "%s","name");
            fprintf(fp, "%s: %s\n",mkstring(buf, 15, LJUST, buf),cma->name.c_str());
            sprintf(buf, "%s","base_pfn");
            fprintf(fp, "%s: 0x%lx\n",mkstring(buf, 15, LJUST, buf),cma->base_pfn);
            sprintf(buf, "%s","end_pfn");
            fprintf(fp, "%s: 0x%lx\n",mkstring(buf, 15, LJUST, buf),(cma->base_pfn + cma->count));
            sprintf(buf, "%s","count");
            fprintf(fp, "%s: %ld\n",mkstring(buf, 15, LJUST, buf),cma->count);
            sprintf(buf, "%s","size");
            fprintf(fp, "%s: 0x%lx\n",mkstring(buf, 15, LJUST, buf),(cma->count << 0x2));
            sprintf(buf, "%s","bitmap");
            fprintf(fp, "%s: 0x%lx",mkstring(buf, 15, LJUST, buf),cma->bitmap);
            // calc how many byte of bitmap
            int nr_byte = (cma->count >> cma->order_per_bit) / 8;
            // calc how many page of one bit
            int nr_pages = (1U << cma->order_per_bit);
            fprintf(fp, " ~ 0x%lx\n",(cma->bitmap + nr_byte));
            fprintf(fp, "========================================================================\n");
            ulong bitmap_addr = cma->bitmap;
            int index = 1;
            for (size_t i = 0; i < nr_byte; i++){
                unsigned char bitmap_data = read_byte(bitmap_addr,"cma bitmap");
                for (size_t j = 0; j < 8; j++){ //bit of one byte
                    int bit_offset = i * 8 + j;
                    ulong base_pfn = cma->base_pfn + bit_offset * nr_pages;
                    bool bit_value = (((bitmap_data >> j) & 0x1) ? true:false);
                    for (size_t k = 0; k < nr_pages; k++){
                        ulong pfn = base_pfn + k;
                        physaddr_t paddr = pfn << 12;
                        ulong page = 0;
                        if (phys_to_page(paddr, &page) && bit_value == alloc) {
                            fprintf(fp, "[%d]PFN:0x%lx paddr:0x%llx page:0x%lx %s\n",index,pfn,(ulonglong)paddr,page,(bit_value ? "allocted":"free"));
                            index += 1;
                        }
                    }
                }
                bitmap_addr += 1;
            }
        }
    }
}

#pragma GCC diagnostic pop
