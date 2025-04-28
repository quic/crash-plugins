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

#include "icc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(ICC)
#endif

void ICC::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (provider_list.size() == 0){
        parser_icc_provider();
    }
    while ((c = getopt(argcnt, args, "apn:r:")) != EOF) {
        switch(c) {
            case 'a':
                print_icc_info();
                break;
            case 'p':
                print_icc_provider();
                break;
            case 'n':
                cppString.assign(optarg);
                print_icc_nodes(cppString);
                break;
            case 'r':
                cppString.assign(optarg);
                print_icc_request(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

ICC::ICC(){
    field_init(icc_provider,provider_list);
    field_init(icc_provider,nodes);
    field_init(icc_provider,dev);
    field_init(icc_provider,users);
    field_init(icc_provider,data);
    struct_init(icc_provider);
    field_init(icc_node,id);
    field_init(icc_node,name);
    field_init(icc_node,node_list);
    field_init(icc_node,avg_bw);
    field_init(icc_node,peak_bw);
    field_init(icc_node,init_avg);
    field_init(icc_node,init_peak);
    field_init(icc_node,data);
    field_init(icc_node,req_list);
    struct_init(icc_node);
    field_init(icc_req,req_node);
    field_init(icc_req,dev);
    field_init(icc_req,enabled);
    field_init(icc_req,tag);
    field_init(icc_req,avg_bw);
    field_init(icc_req,peak_bw);
    struct_init(icc_req);
    cmd_name = "icc";
    help_str_list={
        "icc",                            /* command name */
        "dump icc information",        /* short description */
        "-a \n"
            "  icc -p\n"
            "  icc -n <icc provider name>\n"
            "  icc -r <icc node name>\n"
            "  This command dumps the cma info.",
        "\n",
        "EXAMPLES",
        "  Display all icc provider/node/request info:",
        "    %s> icc -a",
        "    icc_provider:ffffff8002241140 soc:interconnect",
        "       icc_node:ffffff8002106980 avg_bw:2 peak_bw:1 [qup0_core_master]",
        "           icc_req:ffffff801adf7990 avg_bw:76800 peak_bw:76800 [4a90000.spi]",
        "           icc_req:ffffff801adf7790 avg_bw:1 peak_bw:1 [4a84000.i2c]",
        "           icc_req:ffffff8019444e10 avg_bw:1 peak_bw:1 [4a80000.i2c]",
        "\n",
        "  Display all icc provider:",
        "    %s> icc -p",
        "    icc_provider     users data             Name",
        "    ffffff8002241140 10    ffffff8006998040 soc:interconnect",
        "    ffffff8002249d40 12    ffffff800699c040 soc:interconnect@0",
        "    ffffff8002249b40 12    ffffff8002220040 soc:interconnect@1",
        "    ffffff8002249340 30    ffffff8002224040 1900000.interconnect",
        "\n",
        "  Display all icc node of specified provider by provider name:",
        "    %s> icc -n 4480000.interconnect",
        "    icc_node         id    avg_bw     peak_bw    data             Name",
        "    ffffff8002254400 0     478572     2188000    ffffffeedf05e1f0 apps_proc",
        "    ffffff800224b480 1     0          0          ffffffeedf05e360 mas_snoc_bimc_rt",
        "    ffffff800224be80 2     0          0          ffffffeedf05e4d0 mas_snoc_bimc_nrt",
        "    ffffff8002254f80 3     396800     2160000    ffffffeedf05e640 mas_snoc_bimc",
        "\n",
        "  Display all icc request of specified node by node name:",
        "    %s> icc -r apps_proc",
        "    icc_req          enabled tag  avg_bw     peak_bw    Name",
        "    ffffff8018162e10 true    0    0          40000      4e00000.hsusb",
        "    ffffff801a28aa10 true    0    0          0          4453000.qrng",
        "    ffffff8018e09410 false   0    76800      76800      4a90000.spi",
        "    ffffff8018e08410 false   0    1          1          4a84000.i2c",
        "    ffffff80157b7a10 true    0    1          1          4a80000.i2c",
        "\n",
    };
    initialize();
}

void ICC::print_icc_request(std::string node_name){
    for (const auto& provider_ptr : provider_list) {
        for (const auto& node_ptr : provider_ptr->node_list) {
            if (node_ptr->name != node_name){
                continue;
            }
            if(node_ptr->req_list.size() == 0) return;
            std::ostringstream oss_hd;
            oss_hd  << std::left << std::setw(VADDR_PRLEN)  << "icc_req" << " "
                    << std::left << std::setw(7)            << "enabled" << " "
                    << std::left << std::setw(4)            << "tag" << " "
                    << std::left << std::setw(10)           << "avg_bw" << " "
                    << std::left << std::setw(10)           << "peak_bw" << " "
                    << std::left << "Name";
            fprintf(fp, "%s \n",oss_hd.str().c_str());
            for (const auto& req_ptr : node_ptr->req_list) {
                std::ostringstream oss;
                oss << std::left << std::setw(VADDR_PRLEN)  << std::hex << req_ptr->addr << " "
                    << std::left << std::setw(7)            << (req_ptr->enabled ? "true": "false") << " "
                    << std::left << std::setw(4)            << std::dec << req_ptr->tag << " "
                    << std::left << std::setw(10)           << std::dec << req_ptr->avg_bw << " "
                    << std::left << std::setw(10)           << std::dec << req_ptr->peak_bw << " "
                    << std::left << req_ptr->name;
                fprintf(fp, "%s \n",oss.str().c_str());
            }
        }
    }
}

void ICC::print_icc_nodes(std::string provider_name){
    for (const auto& provider_ptr : provider_list) {
        if (provider_ptr->name != provider_name){
            continue;
        }
        if(provider_ptr->node_list.size() == 0) return;
        std::ostringstream oss_hd;
        oss_hd  << std::left << std::setw(VADDR_PRLEN)  << "icc_node" << " "
                << std::left << std::setw(5)            << "id" << " "
                << std::left << std::setw(10)           << "avg_bw" << " "
                << std::left << std::setw(10)           << "peak_bw" << " "
                << std::left << std::setw(16)  << "qcom_icc_node" << " "
                << std::left << "Name";
        fprintf(fp, "%s \n",oss_hd.str().c_str());
        for (const auto& node_ptr : provider_ptr->node_list) {
            std::ostringstream oss;
            oss << std::left << std::setw(VADDR_PRLEN)  << std::hex << node_ptr->addr << " "
                << std::left << std::setw(5)            << std::dec << node_ptr->id << " "
                << std::left << std::setw(10)           << std::dec << node_ptr->avg_bw << " "
                << std::left << std::setw(10)           << std::dec << node_ptr->peak_bw << " "
                << std::left << std::setw(16)           << std::hex << node_ptr->data << " "
                << std::left << node_ptr->name;
            fprintf(fp, "%s \n",oss.str().c_str());
        }
    }
}

void ICC::print_icc_info(){
    for (const auto& provider_ptr : provider_list) {
        std::ostringstream provider;
        provider << std::left << "icc_provider:"   << std::hex << provider_ptr->addr << " "
            << std::left << provider_ptr->name;
        fprintf(fp, "%s \n",provider.str().c_str());
        for (const auto& node_ptr : provider_ptr->node_list) {
            std::ostringstream node;
            node << std::left << "    icc_node:"  << std::hex << node_ptr->addr << " "
                << std::left << "avg_bw:" << std::dec << node_ptr->avg_bw << " "
                << std::left << "peak_bw:" << std::dec << node_ptr->peak_bw << " "
                << std::left << "[" << node_ptr->name << "]";
            fprintf(fp, "%s \n",node.str().c_str());
            for (const auto& req_ptr : node_ptr->req_list) {
                std::ostringstream req;
                req << std::left << "       icc_req:" << std::hex << req_ptr->addr << " "
                    << std::left << "avg_bw:" << std::dec << req_ptr->avg_bw << " "
                    << std::left << "peak_bw:" << std::dec << req_ptr->peak_bw << " "
                    << std::left << "[" << req_ptr->name << "]";
                fprintf(fp, "%s \n",req.str().c_str());
            }
        }
        fprintf(fp, "\n\n");
    }
}

void ICC::print_icc_provider(){
    if(provider_list.size() == 0) return;
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(VADDR_PRLEN)   << "icc_provider" << " "
            << std::left << std::setw(5)    << "users" << " "
            // << std::left << std::setw(VADDR_PRLEN)    << "data" << " "
            << std::left << "Name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& provider_ptr : provider_list) {
        std::ostringstream oss;
        oss << std::left << std::setw(VADDR_PRLEN)   << std::hex << provider_ptr->addr << " "
            << std::left << std::setw(5)    << std::dec << provider_ptr->users << " "
            // << std::left << std::setw(VADDR_PRLEN)    << std::hex << provider_ptr->data << " "
            << std::left << provider_ptr->name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void ICC::parser_icc_provider(){
    if (!csymbol_exists("icc_providers")){
        fprintf(fp, "icc_providers doesn't exist in this kernel!\n");
        return;
    }
    ulong icc_providers_addr = csymbol_value("icc_providers");
    if (!is_kvaddr(icc_providers_addr)) {
        fprintf(fp, "icc_providers address is invalid!\n");
        return;
    }
    int offset = field_offset(icc_provider, provider_list);
    for (const auto& addr : for_each_list(icc_providers_addr,offset)) {
        std::shared_ptr<icc_provider> provider_ptr = std::make_shared<icc_provider>();
        provider_ptr->addr = addr;
        // provider_ptr->data = read_pointer(addr + field_offset(icc_provider,data),"data");
        provider_ptr->users = read_int(addr + field_offset(icc_provider,users),"users");
        ulong dev_addr = read_pointer(addr + field_offset(icc_provider,dev),"dev");
        ulong nodes_addr = addr + field_offset(icc_provider,nodes);
        if (is_kvaddr(dev_addr)){
            ulong name_addr = read_pointer(dev_addr,"name addr");
            if (is_kvaddr(name_addr)){
                provider_ptr->name = read_cstring(name_addr,64, "name");
            }
        }
        parser_icc_node(provider_ptr,nodes_addr);
        provider_list.push_back(provider_ptr);
    }
}

void ICC::parser_icc_node(std::shared_ptr<icc_provider> provider_ptr,ulong head){
    int offset = field_offset(icc_node, node_list);
    for (const auto& addr : for_each_list(head,offset)) {
        void *node_buf = read_struct(addr,"icc_node");
        if (!node_buf) {
            continue;
        }
        std::shared_ptr<icc_node> node_ptr = std::make_shared<icc_node>();
        node_ptr->addr = addr;
        node_ptr->id = UINT(node_buf + field_offset(icc_node,id));
        node_ptr->avg_bw = UINT(node_buf + field_offset(icc_node,avg_bw));
        node_ptr->peak_bw = UINT(node_buf + field_offset(icc_node,peak_bw));
        node_ptr->data = ULONG(node_buf + field_offset(icc_node,data));
        FREEBUF(node_buf);
        ulong name_addr = read_pointer(addr + field_offset(icc_node,name),"name addr");
        if (is_kvaddr(name_addr)){
            node_ptr->name = read_cstring(name_addr,64, "name");
        }
        provider_ptr->node_list.push_back(node_ptr);
        parser_icc_req(node_ptr, addr + field_offset(icc_node,req_list));
    }
}

void ICC::parser_icc_req(std::shared_ptr<icc_node> node_ptr,ulong head){
    int offset = field_offset(icc_req, req_node);
    for (const auto& addr : for_each_hlist(head,offset)) {
        void *req_buf = read_struct(addr,"icc_req");
        if (!req_buf) {
            continue;
        }
        std::shared_ptr<icc_req> req_ptr = std::make_shared<icc_req>();
        req_ptr->addr = addr;
        req_ptr->tag = UINT(req_buf + field_offset(icc_req,tag));
        req_ptr->avg_bw = UINT(req_buf + field_offset(icc_req,avg_bw));
        req_ptr->peak_bw = UINT(req_buf + field_offset(icc_req,peak_bw));
        req_ptr->enabled = BOOL(req_buf + field_offset(icc_req,enabled));
        ulong dev_addr = ULONG(req_buf + field_offset(icc_req,dev));
        FREEBUF(req_buf);
        if (is_kvaddr(dev_addr)){
            ulong name_addr = read_pointer(dev_addr,"name addr");
            if (is_kvaddr(name_addr)){
                req_ptr->name = read_cstring(name_addr,64, "name");
            }
        }
        node_ptr->req_list.push_back(req_ptr);
    }
}
#pragma GCC diagnostic pop
