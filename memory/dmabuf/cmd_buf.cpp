/**
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

/**
 * @brief Main command handler for dmabuf plugin
 *
 * This function processes command-line arguments and dispatches to appropriate
 * handlers for DMA buffer and heap analysis. It supports multiple operations:
 * - Listing and displaying DMA buffers
 * - Analyzing heap information
 * - Tracking per-process buffer usage
 * - Exporting buffer contents
 *
 * The function uses lazy initialization for dmabuf_ptr and heap_ptr to avoid
 * unnecessary parsing overhead when not needed.
 */
void DmaIon::cmd_main(void) {
    int c;
    std::string cppString;

    // Validate minimum argument count
    if (argcnt < 2) {
        LOGW("Insufficient arguments provided (argcnt=%d)", argcnt);
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    // Lazy initialization of DMA buffer parser
    // Only parse DMA buffers when first needed to improve performance
    if (dmabuf_ptr == nullptr) {
        dmabuf_ptr = std::make_shared<Dmabuf>();
        dmabuf_ptr->get_dmabuf_from_proc();
        dmabuf_ptr->parser_dma_bufs();
    }

    // Lazy initialization of heap parser
    // Automatically detect whether to use DMA heap or ION heap based on kernel structures
    if (heap_ptr == nullptr) {
        // Check if modern DMA heap structure exists
        if (struct_size(dma_heap) != -1) {
            LOGD("Detected DMA heap support, using DmaHeap parser");
            heap_ptr = std::make_shared<DmaHeap>(dmabuf_ptr);
            heap_ptr->parser_heaps();
        }
        // Fall back to legacy ION heap if DMA heap not available
        else if (struct_size(ion_heap) != -1) {
            LOGD("Detected ION heap support, using IonHeap parser");
            heap_ptr = std::make_shared<IonHeap>(dmabuf_ptr);
        } else {
            LOGW("No heap structure detected (neither dma_heap nor ion_heap)");
        }
    }
    // Parse command-line options
    while ((c = getopt(argcnt, args, "abB:hH:pP:sS:")) != EOF) {
        switch(c) {
            case 'a':
                // Print all DMA buffer information with detailed metadata
                dmabuf_ptr->print_dma_buf_info();
                break;

            case 'b':
                // Print concise list of all DMA buffers
                dmabuf_ptr->print_dma_buf_list();
                break;

            case 'B':
                // Print detailed information for specific DMA buffer by address
                cppString.assign(optarg);
                dmabuf_ptr->print_dma_buf(cppString);
                break;

            case 'h':
                // Print summary of all heaps
                if (heap_ptr) {
                    heap_ptr->print_heaps();
                } else {
                    LOGE("Heap parser not initialized");
                }
                break;

            case 'H':
                // Print detailed information for specific heap by name
                cppString.assign(optarg);
                if (heap_ptr) {
                    heap_ptr->print_heap(cppString);
                } else {
                    LOGE("Heap parser not initialized");
                }
                break;

            case 'p':
                // Print DMA buffer usage statistics per process
                dmabuf_ptr->print_procs();
                break;

            case 'P':
                // Print DMA buffers for specific process by PID
                try {
                    int pid = std::stoi(optarg);
                    dmabuf_ptr->print_proc(pid);
                } catch (const std::invalid_argument& e) {
                    LOGE("Invalid PID argument: %s (error: %s)", optarg, e.what());
                } catch (const std::out_of_range& e) {
                    LOGE("PID out of range: %s (error: %s)", optarg, e.what());
                }
                break;

            case 's':
                // Print system heap memory pool information
                if (heap_ptr) {
                    heap_ptr->print_system_heap_pool();
                } else {
                    LOGE("Heap parser not initialized");
                }
                break;

            case 'S':
                // Save DMA buffer contents to file
                cppString.assign(optarg);
                dmabuf_ptr->save_dma_buf(cppString);
                break;

            default:
                // Invalid option provided
                LOGW("Invalid option encountered: %c", c);
                argerrs++;
                break;
        }
    }

    // Display usage if any argument errors occurred
    if (argerrs) {
        LOGW("Argument errors detected (argerrs=%d), displaying usage", argerrs);
        cmd_usage(pc->curcmd, SYNOPSIS);
    }
}

/**
 * @brief Initialize kernel structure offsets
 *
 * Registers the kernel structure definitions needed for parsing DMA buffers
 * and heaps. This allows the plugin to correctly interpret memory layouts
 * from different kernel versions.
 *
 * Structures initialized:
 * - dma_heap: Modern DMA-BUF heap allocator (kernel 5.6+)
 * - ion_heap: Legacy ION heap allocator (older kernels)
 */
void DmaIon::init_offset(void) {
    // Initialize DMA heap structure (modern kernel)
    struct_init(dma_heap);

    // Initialize ION heap structure (legacy kernel)
    struct_init(ion_heap);
}

/**
 * @brief Initialize command metadata and help information
 *
 * Sets up the command name, description, and comprehensive help text
 * including usage examples for all supported operations. This information
 * is displayed when users request help or provide invalid arguments.
 */
void DmaIon::init_command(void) {
    // Set command name as it appears in the crash utility
    cmd_name = "dmabuf";
    // Define comprehensive help text with examples
    help_str_list = {
        "dmabuf",                            /* command name */
        "dump dmabuf information",           /* short description */
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
}

/**
 * @brief Constructor for DmaIon plugin
 *
 * Initializes the plugin instance. Member variables (dmabuf_ptr and heap_ptr)
 * are initialized to nullptr and will be lazily created when first needed
 * in cmd_main() to optimize performance.
 */
DmaIon::DmaIon() {

}

#pragma GCC diagnostic pop
