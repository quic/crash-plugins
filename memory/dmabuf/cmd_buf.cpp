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
    while ((c = getopt(argcnt, args, "bB:hH:pP:sS:")) != EOF) {
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
                heap_ptr->print_system_heap_pool();
                break;
            case 'S':
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
        "-b \n"
            "  dmabuf -B <dmabuf addr>\n"
            "  dmabuf -h\n"
            "  dmabuf -H <heap name>\n"
            "  dmabuf -p \n"
            "  dmabuf -P <pid>\n"
            "  dmabuf -s \n"
            "  dmabuf -S <dmabuf addr>\n"
            "  This command dumps the dmabuf information.",
            "\n",
        "EXAMPLES",
        "  Display all dmabuf:",
        "    %s> dmabuf -b",
        "       =======================================================================================",
        "       [001]dma_buf:ffffff80ce9d1c00 ref:3  priv:ffffff80a9774a80 ops::system_heap_buf_ops [system] size:256KB",
        "       [002]dma_buf:ffffff80b9503800 ref:3  priv:ffffff80a9774900 ops::system_heap_buf_ops [system] size:256KB",
        "       =======================================================================================",
        "       Total size:1.58MB",
        "\n",
        "  Display dmabuf detail info:",
        "    %s> dmabuf -B ffffff80ce9d1c00",
        "       dma_buf:ffffff80ce9d1c00 ref:3  priv:ffffff80a9774a80  [system] sg_table:ffffff80a9774ad8 size:256KB",
        "           dma_buf_attachment:ffffff80be58f4e0 dir:DMA_BIDIRECTIONAL priv:ffffff80b662d1c0 device:[26300000.remoteproc:glink-edge:fastrpc:compute-cb@1] driver:[qcom,fastrpc-cb]",
        "           pid:1030  [cdsprpcd] fd:11",
        "           scatterlist:ffffff80a9774480 page:fffffffe038c3000 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744a0 page:fffffffe038c3400 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744c0 page:fffffffe038c3800 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744e0 page:fffffffe038c3c00 offset:0 length:64KB dma_address:0 dma_length:0B",
        "\n",
        "  Display the heap info:",
        "    %s> dmabuf -h ",
        "   dma_heap           Name                    ref  ops               priv               buf_cnt total_size",
        "   ffffff80a4541600   reserved                1    cma_heap_ops      ffffff80a453e580   0       0B",
        "   ffffff80a45419c0   system                  1    system_heap_ops   0                  12      1.02MB"
        "\n",
        "  Display dmabuf detail info for specified heap with heap name:",
        "    %s> dmabuf -H system",
        "       dma_buf:ffffff80ce9d1c00 ref:3  priv:ffffff80a9774a80  [system] sg_table:ffffff80a9774ad8 size:256KB",
        "           dma_buf_attachment:ffffff80be58f4e0 dir:DMA_BIDIRECTIONAL priv:ffffff80b662d1c0 device:[26300000.remoteproc:glink-edge:fastrpc:compute-cb@1] driver:[qcom,fastrpc-cb]",
        "           pid:1030  [cdsprpcd] fd:11",
        "           scatterlist:ffffff80a9774480 page:fffffffe038c3000 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744a0 page:fffffffe038c3400 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744c0 page:fffffffe038c3800 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744e0 page:fffffffe038c3c00 offset:0 length:64KB dma_address:0 dma_length:0B",
        "\n",
        "  Display dmabuf size for process:",
        "    %s> dmabuf -p",
        "       PID   Comm                 buf_cnt  total_size",
        "       1010  adsprpcd             3        264KB",
        "       1011  audioadsprpcd        2        220KB",
        "       1020  cdsprpcd             3        264KB",
        "       1459  pulseaudio           1        32KB"
        "\n",
        "  Display dmabuf detail info for specified process with pid:",
        "    %s> dmabuf -P 1459",
        "       dma_buf:ffffff80ce9d1c00 ref:3  priv:ffffff80a9774a80  [system] sg_table:ffffff80a9774ad8 size:256KB",
        "           dma_buf_attachment:ffffff80be58f4e0 dir:DMA_BIDIRECTIONAL priv:ffffff80b662d1c0 device:[26300000.remoteproc:glink-edge:fastrpc:compute-cb@1] driver:[qcom,fastrpc-cb]",
        "           pid:1030  [cdsprpcd] fd:11",
        "           scatterlist:ffffff80a9774480 page:fffffffe038c3000 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744a0 page:fffffffe038c3400 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744c0 page:fffffffe038c3800 offset:0 length:64KB dma_address:0 dma_length:0B",
        "           scatterlist:ffffff80a97744e0 page:fffffffe038c3c00 offset:0 length:64KB dma_address:0 dma_length:0B",
        "\n",
        "  Display the memory pool of system heap:",
        "    %s> dmabuf -s",
        "       system:",
        "           page_pool          order high       low        total",
        "           ffffff8024374a80   9     0B         108MB      108MB",
        "           ffffff8024374240   4     0B         79.69MB    79.69MB",
        "           ffffff80243743c0   0     0B         368KB      368KB",
        "",
        "       qcom,system:",
        "           page_pool          order high       low        total",
        "           ffffff8024374a80   9     0B         108MB      108MB",
        "           ffffff8024374240   4     0B         79.69MB    79.69MB",
        "           ffffff80243743c0   0     0B         368KB      368KB"
        "\n",
        "  Save a dmabuf data to file:",
        "    %s> dmabuf -S ffffff88d0010400",
        "       Save dmabuf to file xxx/dma_buf@ffffff88d0010400.data !",
        "\n",
    };
    initialize();
}

#pragma GCC diagnostic pop
