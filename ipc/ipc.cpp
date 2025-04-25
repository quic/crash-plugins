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

#include "ipc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(IPCLog)
#endif

void IPCLog::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "al:")) != EOF) {
        switch(c) {
            case 'a':
                parser_ipc_log();
                break;
            case 'l':
                cppString.assign(optarg);
                parser_ipc_log(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

IPCLog::IPCLog(){
    field_init(ipc_log_context,magic);
    field_init(ipc_log_context,version);
    field_init(ipc_log_context,user_version);
    field_init(ipc_log_context,name);
    field_init(ipc_log_context,list);
    field_init(ipc_log_context,first_page);
    field_init(ipc_log_context,last_page);
    field_init(ipc_log_context,write_page);
    field_init(ipc_log_context,read_page);
    field_init(ipc_log_context,nd_read_page);
    field_init(ipc_log_context,write_avail);
    field_init(ipc_log_context,page_list);
    struct_init(ipc_log_context);

    field_init(ipc_log_page,hdr);
    field_init(ipc_log_page,data);
    field_init(ipc_log_page_header,magic);
    field_init(ipc_log_page_header,write_offset);
    field_init(ipc_log_page_header,start_time);
    field_init(ipc_log_page_header,end_time);
    field_init(ipc_log_page_header,nd_read_offset);
    field_init(ipc_log_page_header,list);
    struct_init(ipc_log_page_header);
    struct_init(ipc_log_page);
    struct_init(tsv_header);
    cmd_name = "ipc";
    help_str_list={
        "ipc",                            /* command name */
        "dump ipc log",        /* short description */
        "-a \n"
            "  ipc -l <ipc module name>\n"
            "  This command dumps the ipc module log.",
        "\n",
        "EXAMPLES",
        "  Display all ipc_log_context:",
        "    %s> ipc -a",
        "    ipc_log_context  Magic      Version first_page       last_page        write_page       read_page        Name",
        "    ffffff80084bfd00 25874452   3       ffffff800a3b7000 ffffff8008628000 ffffff800a3b1000 ffffff800a3b1000 rpm-glink",
        "    ffffff8008654500 25874452   3       ffffff800863d000 ffffff800863b000 ffffff800863a000 ffffff800863a000 qrtr_ns",
        "    ffffff800a721600 25874452   3       ffffff8008705000 ffffff8013304000 ffffff8008705000 ffffff8008705000 mmc0",
        "    ffffff80180c5c00 25874452   3       ffffff801496b000 ffffff8015d7b000 ffffff801496e000 ffffff801496e000 glink_pkt",
        "\n",
        "  Display ipc log of specified context by name:",
        "    %s> ipc -l adsp_region",
        "    [ 161.448574138 0x90dee57d91b]   [glink_pkt_poll]: Exit channel:location_ctrl",
        "    [ 161.448616117 0x90dee57dc3f]   [glink_pkt_poll]: Wait for pkt on channel:location_ctrl",
        "    [ 161.448627731 0x90dee57dd1d]   [glink_pkt_poll]: Exit channel:location_ctrl",
        "    [ 161.475913096 0x90dee5fdb85]   [glink_pkt_rpdev_copy_cb]: Data received on:ss_bt_ctrl len:60",
        "    [ 161.475946481 0x90dee5fde06]   [glink_pkt_rpdev_copy_cb]: Data queued on:ss_bt_ctrl len:60",
        "    [ 161.475976325 0x90dee5fe043]   [glink_pkt_poll]: Wait for pkt on channel:ss_bt_ctrl",
        "\n",
    };
    initialize();
}

void IPCLog::parser_ipc_log(std::string name){
    if (!csymbol_exists("ipc_log_context_list")){
        fprintf(fp, "ipc_log_context_list doesn't exist in this kernel!\n");
        return;
    }
    size_t list_head = csymbol_value("ipc_log_context_list");
    if (!is_kvaddr(list_head)) {
        fprintf(fp, "ipc_log_context_list address is invalid!\n");
        return;
    }
    int offset = field_offset(ipc_log_context, list);
    for (const auto& ctx_addr : for_each_list(list_head,offset)) {
        std::string ipc_name = read_cstring(ctx_addr + field_offset(ipc_log_context,name),32, "name");
        if (ipc_name.empty() || name != ipc_name){
            continue;
        }
        ulong nd_read_page = read_ulong(ctx_addr + field_offset(ipc_log_context,nd_read_page),"nd_read_page");
        uint32_t magic = read_ulong(nd_read_page + field_offset(ipc_log_page,hdr) + field_offset(ipc_log_page_header,magic),"magic");
        if (magic != IPC_LOGGING_MAGIC_NUM){
            continue;
        }
        ulong page_list = ctx_addr + field_offset(ipc_log_context,page_list);
        // int list_off = field_offset(ipc_log_page_header, list);
        // for (const auto& header_addr : for_each_list(page_list,list_off)) {
        //     ulong log_page_addr = header_addr - field_offset(ipc_log_page,hdr);
        //     fprintf(fp, "ipc_log_page:%#lx \n",log_page_addr);
        // }
        parser_ipc_log_page(nd_read_page,page_list);
    }
}

void IPCLog::parser_ipc_log_page(ulong addr,ulong page_list){
    ulong curr_read_page = addr;
    uint16_t write_offset = read_ushort(curr_read_page + field_offset(ipc_log_page,hdr)
            + field_offset(ipc_log_page_header,write_offset),"write_offset");
    uint16_t nd_read_offset = read_ushort(curr_read_page + field_offset(ipc_log_page,hdr)
            + field_offset(ipc_log_page_header,nd_read_offset),"nd_read_offset");
    bool wrapped_around = false;
    if (nd_read_offset <= write_offset){
        wrapped_around = false;
    }else{
        wrapped_around = true;
    }
    std::vector<char> ipcLogBuf;
    size_t bytes_to_copy = 0;
    ulong start_addr = 0;
    void* data_buf = nullptr;
    while (is_kvaddr(curr_read_page)){
        // fprintf(fp, "ipc_log_page:%#lx \n",curr_read_page);
        void *log_page_buf = read_struct(curr_read_page,"ipc_log_page");
        if (!log_page_buf) {
            return;
        }
        write_offset = USHORT(log_page_buf + field_offset(ipc_log_page,hdr) + field_offset(ipc_log_page_header,write_offset));
        uint64_t start_time = ULONGLONG(log_page_buf + field_offset(ipc_log_page,hdr) + field_offset(ipc_log_page_header,start_time));
        uint64_t end_time = ULONGLONG(log_page_buf + field_offset(ipc_log_page,hdr) + field_offset(ipc_log_page_header,end_time));
        nd_read_offset = USHORT(log_page_buf + field_offset(ipc_log_page,hdr) + field_offset(ipc_log_page_header,nd_read_offset));
        FREEBUF(log_page_buf);

        if (nd_read_offset <= write_offset){
            bytes_to_copy = write_offset - nd_read_offset;
        }else{
            bytes_to_copy = field_size(ipc_log_page,data) - nd_read_offset;
        }
        if (bytes_to_copy <= 0){
            break;
        }
        start_addr = curr_read_page + field_offset(ipc_log_page,data) + nd_read_offset;
        data_buf = read_memory(start_addr,bytes_to_copy,"data");
        appendBuffer(ipcLogBuf, data_buf, bytes_to_copy);
        FREEBUF(data_buf);
        // fprintf(fp, "bytes_to_copy:%d \n",bytes_to_copy);
        if (wrapped_around == false && write_offset < field_size(ipc_log_page,data)){
            break;
        }
        ulong list_addr = curr_read_page + field_offset(ipc_log_page,hdr) + field_offset(ipc_log_page_header,list);
        ulong list = read_pointer(list_addr,"list");
        if (list == page_list){
            list = read_pointer(list,"list");
        }
        curr_read_page = list - field_offset(ipc_log_page_header,list) - field_offset(ipc_log_page,hdr);
        if (curr_read_page == addr){
            break;
        }
    }
    if (wrapped_around){
        write_offset = read_ushort(addr + field_offset(ipc_log_page,hdr) + field_offset(ipc_log_page_header,write_offset),"write_offset");
        bytes_to_copy = write_offset;
        start_addr = addr + field_offset(ipc_log_page,data);
        data_buf = read_memory(start_addr,bytes_to_copy,"data");
        appendBuffer(ipcLogBuf, data_buf, bytes_to_copy);
        FREEBUF(data_buf);
    }

    size_t len = 0;
    char* dataPtr = ipcLogBuf.data();
    uint64_t TimeStamp = 0;
    uint64_t TimeQtimer = 0;
    while (len < ipcLogBuf.size()) {
        tsv_header header = *reinterpret_cast<tsv_header*>(dataPtr);
        len += sizeof(tsv_header);
        dataPtr += sizeof(tsv_header);

        tsv_header msg = *reinterpret_cast<tsv_header*>(dataPtr);
        len += sizeof(tsv_header);
        dataPtr += sizeof(tsv_header);
        if (msg.type == TSV_TYPE_TIMESTAMP){
            if (msg.size == 4){
                TimeStamp = *reinterpret_cast<uint32_t*>(dataPtr);
            }else if (msg.size == 8){
                TimeStamp = *reinterpret_cast<uint64_t*>(dataPtr);
            }
            len += msg.size;
            dataPtr += msg.size;
        }
        msg = *reinterpret_cast<tsv_header*>(dataPtr);
        len += sizeof(tsv_header);
        dataPtr += sizeof(tsv_header);
        if (msg.type == TSV_TYPE_QTIMER){
            if (msg.size == 4){
                TimeQtimer = *reinterpret_cast<uint32_t*>(dataPtr);
            }else if (msg.size == 8){
                TimeQtimer = *reinterpret_cast<uint64_t*>(dataPtr);
            }
            len += msg.size;
            dataPtr += msg.size;
        }
        msg = *reinterpret_cast<tsv_header*>(dataPtr);
        len += sizeof(tsv_header);
        dataPtr += sizeof(tsv_header);
        if (msg.type == TSV_TYPE_BYTE_ARRAY){
            std::string str_data(dataPtr, msg.size);
            std::ostringstream oss;
            if (str_data.find('\n') != std::string::npos) {
                oss << "[ " << std::fixed << std::setprecision(9) << TimeStamp / 1000000000.0 << " 0x" << std::hex << TimeQtimer << "]   " << str_data;
            } else {
                oss << "[ " << std::fixed << std::setprecision(9) << TimeStamp / 1000000000.0 << " 0x" << std::hex << TimeQtimer << "]   " << str_data << "\n";
            }
            fprintf(fp, "%s",oss.str().c_str());
            len += msg.size;
            dataPtr += msg.size;
        }
    }
}

void IPCLog::appendBuffer(std::vector<char>& destBuf, void* sourceBuf, size_t length) {
    size_t currentSize = destBuf.size();
    destBuf.resize(currentSize + length);
    memcpy(destBuf.data() + currentSize, sourceBuf, length);
}

void IPCLog::parser_ipc_log(){
    if (!csymbol_exists("ipc_log_context_list")){
        fprintf(fp, "ipc_log_context_list doesn't exist in this kernel!\n");
        return;
    }
    size_t list_head = csymbol_value("ipc_log_context_list");
    if (!is_kvaddr(list_head)) {
        fprintf(fp, "ipc_log_context_list address is invalid!\n");
        return;
    }
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(VADDR_PRLEN)  << "ipc_log_context" << " "
            << std::left << std::setw(10)           << "Magic"              << " "
            << std::left << std::setw(7)            << "Version"            << " "
            << std::left << std::setw(VADDR_PRLEN)  << "first_page"         << " "
            << std::left << std::setw(VADDR_PRLEN)  << "last_page"          << " "
            << std::left << std::setw(VADDR_PRLEN)  << "write_page"         << " "
            << std::left << std::setw(VADDR_PRLEN)  << "read_page"          << " "
            << std::left << "Name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    int offset = field_offset(ipc_log_context, list);
    for (const auto& ctx_addr : for_each_list(list_head,offset)) {
        std::string name = read_cstring(ctx_addr + field_offset(ipc_log_context,name),32, "name");
        void *ctx_buf = read_struct(ctx_addr,"ipc_log_context");
        if (!ctx_buf) {
            continue;
        }
        uint32_t magic = UINT(ctx_buf + field_offset(ipc_log_context,magic));
        if (magic != IPC_LOG_CONTEXT_MAGIC_NUM){
            FREEBUF(ctx_buf);
            continue;
        }
        uint32_t version = UINT(ctx_buf + field_offset(ipc_log_context,version));
        ulong first_page = ULONG(ctx_buf + field_offset(ipc_log_context,first_page));
        ulong last_page = ULONG(ctx_buf + field_offset(ipc_log_context,last_page));
        ulong write_page = ULONG(ctx_buf + field_offset(ipc_log_context,write_page));
        ulong read_page = ULONG(ctx_buf + field_offset(ipc_log_context,read_page));
        ulong nd_read_page = ULONG(ctx_buf + field_offset(ipc_log_context,nd_read_page));
        uint32_t write_avail = UINT(ctx_buf + field_offset(ipc_log_context,write_avail));
        FREEBUF(ctx_buf);
        std::ostringstream oss;
        oss << std::left << std::setw(VADDR_PRLEN)  << std::hex << ctx_addr     << " "
            << std::left << std::setw(10)           << std::hex << magic        << " "
            << std::left << std::setw(7)            << std::dec << version      << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << first_page   << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << last_page    << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << write_page   << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << read_page    << " "
            << std::left << name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

#pragma GCC diagnostic pop
