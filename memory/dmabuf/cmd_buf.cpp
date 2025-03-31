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

#include "cmd_buf.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(DmaIon)
#endif

void DmaIon::cmd_main(void) {
    int c;
    int flags;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if(dmabuf_ptr == nullptr){
        dmabuf_ptr = std::make_shared<Dmabuf>();
    }
    if(heap_ptr == nullptr){
        if(struct_size(dma_heap) != -1){
            heap_ptr = std::make_shared<DmaHeap>(dmabuf_ptr);
        }else if(struct_size(ion_heap) != -1){
            heap_ptr = std::make_shared<IonHeap>(dmabuf_ptr);
        }
    }
    while ((c = getopt(argcnt, args, "bB:hH:pP:s:")) != EOF) {
        switch(c) {
            case 'b':
                dmabuf_ptr->print_dma_buf_list();
                break;
            case 'B':
                cppString.assign(optarg);
                dmabuf_ptr->print_dma_buf(cppString);
                break;
            case 'h':
                heap_ptr->print_heaps();
                break;
            case 'H':
                cppString.assign(optarg);
                heap_ptr->print_heap(cppString);
                break;
            case 'p':
                dmabuf_ptr->print_procs();
                break;
            case 'P':
                try {
                    int pid = std::stoi(optarg);
                    dmabuf_ptr->print_proc(pid);
                } catch (const std::invalid_argument& e) {
                    fprintf(fp, "Invalid argument:%s \n",e.what());
                } catch (const std::out_of_range& e) {
                    fprintf(fp, "Out of range:%s \n",e.what());
                }
                break;
            case 's':
                cppString.assign(optarg);
                dmabuf_ptr->save_dma_buf(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

DmaIon::DmaIon(){
    struct_init(dma_heap);
    struct_init(ion_heap);
    // print_table();
    cmd_name = "dmabuf";
    help_str_list={
        "dmabuf",                            /* command name */
        "dump dmabuf information",        /* short description */
        "-a \n"
            "  dmabuf -b\n"
            "  dmabuf -d <dmabuf addr>\n"
            "  This command dumps the dmabuf information.",
            "\n",
        "EXAMPLES",
        "  Display full dmabuf info:",
        "    %s> dmabuf -a",
        "    [1]dma_buf:0xffffff8023fbb800 ref:4 priv:0xffffff806cd37400 size:7.21Mb    [system]           ops:sg_buf_ops",
        "           dma_buf_attachment:0xffffff80332ca680 dir:DMA_BIDIRECTIONAL device:[cam_smmu:cam_smmu_tfe] driver:[cam_smmu] priv:0xffffff806ab50a40",
        "",
        "    [2]dma_buf:0xffffff80521c3000 ref:4 priv:0xffffff806cd49200 size:7.21Mb    [system]           ops:sg_buf_ops",
        "           dma_buf_attachment:0xffffff806cd2fd00 dir:DMA_BIDIRECTIONAL device:[cam_smmu:cam_smmu_tfe] driver:[cam_smmu] priv:0xffffff805beb9dc0",
        "\n",
        "  Display all dmabuf info:",
        "    %s> dmabuf -b",
        "    =======================================================================================",
        "    [1]dma_buf:0xffffff80521c3000 ref:4 priv:0xffffff806cd49200 size:7.21Mb    [system]           ops:sg_buf_ops",
        "    [2]dma_buf:0xffffff8064c21000 ref:4 priv:0xffffff8060214500 size:7.21Mb    [system]           ops:sg_buf_ops",
        "    [3]dma_buf:0xffffff8034321400 ref:4 priv:0xffffff8041da9c00 size:7.21Mb    [system]           ops:sg_buf_ops",
        "    [4]dma_buf:0xffffff802f5c8e00 ref:4 priv:0xffffff8041cdea00 size:7.21Mb    [system]           ops:sg_buf_ops",
        "\n",
        "  Display the detail info of dmabuf by dmabuf address:",
        "    %s> dmabuf -d ",
        "    ========================================================================",
        "    dma_buf        : 0xffffff803516a800",
        "    exp_name       : system-uncached",
        "    ops            : sg_buf_ops",
        "    size           : 3.47Mb",
        "    sg_buffer : 0xffffff8023a98500",
        "    ========================================================================",
        "        dma_buf_attachment:0xffffff8045c1a600 dir:DMA_BIDIRECTIONAL device:[cam_smmu:cam_smmu_ope] driver:[cam_smmu] priv:0xffffff80693dc480",
        "\n",
    };
    initialize();
}

#pragma GCC diagnostic pop
