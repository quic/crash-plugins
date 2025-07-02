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

#include "dmabuf.h"
#include "cmd_buf.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

void Dmabuf::cmd_main(void) {

}

Dmabuf::Dmabuf(){
    field_init(dma_buf,list_node);
    field_init(dma_buf,size);
    field_init(dma_buf,attachments);
    field_init(dma_buf,exp_name);
    field_init(dma_buf,name);
    field_init(dma_buf,priv);
    field_init(dma_buf,file);
    field_init(dma_buf,ops);
    field_init(dma_buf_attachment,node);
    field_init(dma_buf_attachment,dev);
    field_init(dma_buf_attachment,priv);
    field_init(dma_buf_attachment,sgt);
    field_init(dma_buf_attachment,importer_priv);
    field_init(dma_buf_attachment,priv);
    field_init(dma_buf_attachment,dma_map_attrs);
    field_init(dma_buf_attachment,dir);
    field_init(device,kobj);
    field_init(device,driver);
    field_init(kobject,name);
    field_init(device_driver,name);
    field_init(file,private_data);
    field_init(file,f_op);
    field_init(file,f_count);
    field_init(file, f_vfsmnt);
    field_init(ion_buffer,heap);
    field_init(ion_buffer,sg_table);
    field_init(qcom_sg_buffer,heap);
    field_init(qcom_sg_buffer,sg_table);
    field_init(sg_table,sgl);
    field_init(sg_table,nents);
    field_init(scatterlist,offset);
    field_init(scatterlist,length);
    field_init(scatterlist,dma_address);
    field_init(scatterlist,dma_length);
    field_init(scatterlist,page_link);
    struct_init(dma_buf);
    struct_init(dma_buf_attachment);
    struct_init(device);
    struct_init(device_driver);
    struct_init(ion_buffer);
    struct_init(qcom_sg_buffer);
    struct_init(scatterlist);
    // print_table();
    get_dmabuf_from_proc();
    parser_dma_bufs();
}

void Dmabuf::parser_dma_bufs(){
    ulong db_list_addr = 0;
    if (csymbol_exists("db_list")){
        db_list_addr = csymbol_value("db_list");
    }else if (csymbol_exists("debugfs_list")){
        db_list_addr = csymbol_value("debugfs_list");
    }
    if (!is_kvaddr(db_list_addr)){
        fprintf(fp, "db_list doesn't exist in this kernel!\n");
        return;
    }
    for (const auto& buf_addr : for_each_list(db_list_addr,field_offset(dma_buf,list_node))) {
        std::shared_ptr<dma_buf> buf_ptr = parser_dma_buf(buf_addr);
        if (buf_ptr == nullptr){
            continue;
        }
        ulong attachments_head = buf_addr + field_offset(dma_buf,attachments);
        buf_ptr->attachments = parser_attachments(attachments_head);
        get_proc_info(buf_ptr);
        buf_list.push_back(buf_ptr);
    }
}

std::shared_ptr<dma_buf> Dmabuf::parser_dma_buf(ulong addr){
    if (!is_kvaddr(addr)){
        return nullptr;
    }
    void *dmabuf = read_struct(addr,"dma_buf");
    if(dmabuf == nullptr) return nullptr;
    std::shared_ptr<dma_buf> buf_ptr = std::make_shared<dma_buf>();
    buf_ptr->addr = addr;
    buf_ptr->size = INT(dmabuf + field_offset(dma_buf,size));
    buf_ptr->priv = ULONG(dmabuf + field_offset(dma_buf,priv));
    parser_buffer(buf_ptr);
    ulong file_addr = ULONG(dmabuf + field_offset(dma_buf,file));
    if (is_kvaddr(file_addr)){
        char buf[BUFSIZE];
        buf_ptr->f_count = read_long(file_addr + field_offset(file,f_count),"file_f_count");
        if (field_offset(file, f_vfsmnt) != -1) {
            get_pathname(file_to_dentry(file_addr), buf, BUFSIZE, 1, file_to_vfsmnt(file_addr));
        } else {
            get_pathname(file_to_dentry(file_addr), buf, BUFSIZE, 1, 0);
        }
        buf_ptr->file = buf;
    }
    ulong name_addr = ULONG(dmabuf + field_offset(dma_buf,name));
    if (is_kvaddr(name_addr)){
        buf_ptr->name = read_cstring(name_addr,64,"dma_buf_name");
    }
    name_addr = ULONG(dmabuf + field_offset(dma_buf,exp_name));
    if (is_kvaddr(name_addr)){
        buf_ptr->exp_name = read_cstring(name_addr,64,"dma_buf_exp_name");
    }
    ulong ops_addr = ULONG(dmabuf + field_offset(dma_buf,ops));
    ulong offset;
    struct syment *sp = value_search(ops_addr, &offset);
    if (sp) {
        buf_ptr->ops_name = sp->name;
    }
    FREEBUF(dmabuf);
    return buf_ptr;
}

void Dmabuf::parser_buffer(std::shared_ptr<dma_buf> buf_ptr){
    if (!is_kvaddr(buf_ptr->priv)){
        return;
    }
    if (struct_size(ion_buffer) != -1){
        buf_ptr->heap = read_pointer(buf_ptr->priv + field_offset(ion_buffer,heap),"heap");
        buf_ptr->sg_table = read_pointer(buf_ptr->priv + field_offset(ion_buffer,sg_table),"sg_table");
    }else if (struct_size(qcom_sg_buffer) != -1){
        buf_ptr->heap = read_pointer(buf_ptr->priv + field_offset(qcom_sg_buffer,heap),"heap");
        buf_ptr->sg_table = buf_ptr->priv + field_offset(qcom_sg_buffer,sg_table);
    }
    parser_sg_table(buf_ptr);
}

//bit0 = 1 is a chain
bool Dmabuf::sg_is_chain(ulong page_link){
    return (page_link & 0x1) == 1;
}

//bit1 = 1 is last sg
bool Dmabuf::sg_is_last(ulong page_link){
    return (page_link & 0x2) == 2;
}

ulong Dmabuf::sg_chain_ptr(ulong page_link){
    return page_link & ~0x3;
}

ulong Dmabuf::sg_next(ulong sgl_addr, ulong page_link){
    if (sg_is_last(page_link)) {
        return 0;
    }
    if (sg_is_chain(page_link)) {
        return sg_chain_ptr(page_link);
    } else {
        return sgl_addr + struct_size(scatterlist);
    }
}

void Dmabuf::parser_sg_table(std::shared_ptr<dma_buf> buf_ptr){
    if (!is_kvaddr(buf_ptr->sg_table)){
        return;
    }
    ulong sgl_addr = read_pointer(buf_ptr->sg_table + field_offset(sg_table,sgl),"sgl");
    int cnt = read_uint(buf_ptr->sg_table + field_offset(sg_table,nents),"nents");
    // fprintf(fp, "sg_table:%lx \n",buf_ptr->sg_table);
    while (is_kvaddr(sgl_addr) && cnt){
        cnt -= 1;
        std::shared_ptr<scatterlist> sgl_ptr = std::make_shared<scatterlist>();
        void *sgl_buf = read_struct(sgl_addr,"scatterlist");
        if(sgl_buf == nullptr) continue;
        sgl_ptr->addr = sgl_addr;
        sgl_ptr->offset = UINT(sgl_buf + field_offset(scatterlist,offset));
        sgl_ptr->length = UINT(sgl_buf + field_offset(scatterlist,length));
        sgl_ptr->dma_address = ULONG(sgl_buf + field_offset(scatterlist,dma_address));
        sgl_ptr->dma_length = UINT(sgl_buf + field_offset(scatterlist,dma_length));
        sgl_ptr->page_link = ULONG(sgl_buf + field_offset(scatterlist,page_link));
        FREEBUF(sgl_buf);
        // fprintf(fp, "   sgl_addr:%lx dma_address:%lx dma_length:%d\n",sgl_addr,sgl_ptr->dma_address,sgl_ptr->length);
        if (sgl_ptr->page_link == 0){
            break;
        }
        sgl_addr = sg_next(sgl_addr,sgl_ptr->page_link);
        buf_ptr->sgl_list.push_back(sgl_ptr);
    }
}

void Dmabuf::get_dmabuf_from_proc(){
    if (!csymbol_exists("dma_buf_fops")){
        fprintf(fp, "dma_buf_fops doesn't exist in this kernel!\n");
        return;
    }
    ulong dma_buf_fops = csymbol_value("dma_buf_fops");
    for(ulong task_addr: for_each_process()){
        struct task_context *tc = task_to_context(task_addr);
        if (!tc){
            continue;
        }
        std::unordered_map<ulong, int> map;
        std::vector<ulong> files = for_each_task_files(tc);
        for (size_t i = 0; i < files.size(); i++){
            if (!is_kvaddr(files[i])){
                continue;
            }
            ulong f_op = read_pointer(files[i] + field_offset(file,f_op),"f_op");
            if (f_op != dma_buf_fops){
                continue;
            }
            ulong priv = read_pointer(files[i] + field_offset(file,private_data),"private_data");
            if (!is_kvaddr(priv)){
                continue;
            }
            map[priv] = i;
        }
        if (map.size() > 0){
            std::shared_ptr<proc_info> proc_ptr = std::make_shared<proc_info>();
            proc_ptr->tc = tc;
            proc_ptr->fd_map = map;
            proc_list.push_back(proc_ptr);
        }
    }
}

void Dmabuf::get_proc_info(std::shared_ptr<dma_buf> buf_ptr){
    for (const auto& proc_ptr : proc_list){
        for (const auto& pair : proc_ptr->fd_map){
            if (buf_ptr->addr == pair.first){
                buf_ptr->procs.push_back(proc_ptr);
            }
        }
    }
}



std::vector<std::shared_ptr<attachment>> Dmabuf::parser_attachments(ulong list_head){
    std::vector<std::shared_ptr<attachment>> res;
    int offset = field_offset(dma_buf_attachment,node);
    for (const auto& attach_addr : for_each_list(list_head,offset)) {
        void *buf = read_struct(attach_addr,"dma_buf_attachment");
        if(buf == nullptr) continue;
        std::shared_ptr<attachment> attach_ptr = std::make_shared<attachment>();
        attach_ptr->addr = attach_addr;
        attach_ptr->sg_table = ULONG(buf + field_offset(dma_buf_attachment,sgt));
        attach_ptr->importer_priv = ULONG(buf + field_offset(dma_buf_attachment,importer_priv));
        attach_ptr->priv = ULONG(buf + field_offset(dma_buf_attachment,priv));
        attach_ptr->dma_map_attrs = ULONG(buf + field_offset(dma_buf_attachment,dma_map_attrs));
        attach_ptr->dir = (enum dma_data_direction)INT(buf + field_offset(dma_buf_attachment,dir));
        ulong dev_addr = ULONG(buf + field_offset(dma_buf_attachment,dev));
        if (is_kvaddr(dev_addr)){
            void *device_buf = read_struct(dev_addr,"device");
            if(device_buf != nullptr){
                ulong addr = ULONG(device_buf + field_offset(device,kobj) + field_offset(kobject,name));
                if (is_kvaddr(addr)){
                    attach_ptr->device_name = read_cstring(addr,64, "device_name");
                }
                ulong driver_addr = ULONG(device_buf + field_offset(device,driver));
                if (is_kvaddr(driver_addr)){
                    void *driver_buf = read_struct(driver_addr,"device_driver");
                    addr = ULONG(driver_buf + field_offset(device_driver,name));
                    if (is_kvaddr(addr)){
                        attach_ptr->driver_name = read_cstring(addr,64, "driver_name");
                    }
                    FREEBUF(driver_buf);
                }
                FREEBUF(device_buf);
            }
        }
        FREEBUF(buf);
        res.push_back(attach_ptr);
    }
    return res;
}

void Dmabuf::print_dma_buf_list(){
    int index = 1;
    uint64_t total_size = 0;
    if (buf_list.size() == 0){
        return;
    }
    std::sort(buf_list.begin(), buf_list.end(),[&](const std::shared_ptr<dma_buf>& a, const std::shared_ptr<dma_buf>& b){
        return a->size > b->size;
    });
    fprintf(fp, "=======================================================================================\n");
    for (const auto& dma_buf : buf_list) {
        total_size += dma_buf->size;
        std::ostringstream oss;
        oss << "[" << std::setw(3) << std::setfill('0') << index << "]"
            << "dma_buf:" << std::hex <<  std::setfill(' ') << dma_buf->addr << " "
            << "ref:"  << std::left << std::dec << std::setw(2) << dma_buf->f_count << " "
            << "priv:" << std::left << std::hex << dma_buf->priv << " "
            << "ops::" << std::left << std::setw(12) << dma_buf->ops_name << " ["
            << std::left << dma_buf->exp_name << "] "
            << "size:" << std::left << std::setw(9) << csize(dma_buf->size);
        fprintf(fp, "%s \n",oss.str().c_str());
        index += 1;
    }
    fprintf(fp, "=======================================================================================\n");
    fprintf(fp, "Total size:%s\n",csize(total_size).c_str());
    fprintf(fp, " \n");
}

void Dmabuf::print_attachment(std::shared_ptr<dma_buf> buf_ptr){
    for (const auto& attach : buf_ptr->attachments) {
        std::ostringstream oss_a;
        oss_a << "        dma_buf_attachment:" << std::hex <<  std::setfill(' ') << attach->addr << " "
            << "dir:"  << std::left << directions[attach->dir] << " "
            << "priv:" << std::left << std::hex << attach->priv << " "
            << "device:[" << std::left << attach->device_name << "] "
            << "driver:[" << std::left << attach->driver_name << "]";
        fprintf(fp, "%s \n",oss_a.str().c_str());
    }
}

void Dmabuf::print_proc_info(std::shared_ptr<dma_buf> buf_ptr){
    for (const auto& proc : buf_ptr->procs) {
        std::ostringstream oss_a;
        oss_a << "        pid:" << std::dec << std::left << std::setw(5) << proc->tc->pid << " "
            << "["  << std::left << proc->tc->comm << "] "
            << "fd:" << std::left << std::dec << proc->fd_map[buf_ptr->addr] << " ";
        fprintf(fp, "%s \n",oss_a.str().c_str());
    }
}

void Dmabuf::print_sg_table(std::shared_ptr<dma_buf> buf_ptr){
    for (const auto& sgl_ptr : buf_ptr->sgl_list) {
        std::ostringstream oss_a;
        oss_a << "        scatterlist:" << std::hex << std::left << sgl_ptr->addr << " "
            << "page:"  << std::left << std::hex << (sgl_ptr->page_link  & ~ 0x3) << " "
            << "offset:"  << std::left << std::dec << sgl_ptr->offset << " "
            << "length:"  << std::left << std::dec << csize(sgl_ptr->length) << " "
            << "dma_address:"  << std::left << std::hex << sgl_ptr->dma_address << " "
            << "dma_length:"  << std::left << std::dec << csize(sgl_ptr->dma_length);
        fprintf(fp, "%s \n",oss_a.str().c_str());
    }
}

void Dmabuf::print_dma_buf(std::shared_ptr<dma_buf> buf_ptr){
    std::ostringstream oss;
    oss << "dma_buf:" << std::hex <<  std::setfill(' ') << buf_ptr->addr << " "
        << "ref:"  << std::left << std::dec << std::setw(2) << buf_ptr->f_count << " "
        << "priv:" << std::left << std::hex << buf_ptr->priv << " "
        << " [" << std::left << buf_ptr->exp_name << "] "
        << "sg_table:" << std::left << std::hex << buf_ptr->sg_table << " "
        << "size:" << std::left << std::setw(9) << csize(buf_ptr->size);
    fprintf(fp, "%s \n",oss.str().c_str());
    print_attachment(buf_ptr);
    print_proc_info(buf_ptr);
    print_sg_table(buf_ptr);
    fprintf(fp, " \n");
}

void Dmabuf::print_dma_buf(std::string addr){
    unsigned long number = std::stoul(addr, nullptr, 16);
    if (number <= 0){
        return;
    }
    for (const auto& dma_buf : buf_list) {
        if (dma_buf->addr == number) {
            print_dma_buf(dma_buf);
            return;
        }
    }
}

void Dmabuf::save_dma_buf(std::string addr){
    unsigned long number = std::stoul(addr, nullptr, 16);
    if (number <= 0){
        return;
    }
    for (const auto& buf_ptr : buf_list) {
        if (buf_ptr->addr == number) {
            std::stringstream ss = get_curpath();
            ss << "/dma_buf@" << std::hex << buf_ptr->addr << ".data";
            FILE* dma_file = fopen(ss.str().c_str(), "wb");
            if (!dma_file) {
                fprintf(fp, "Can't open %s\n", ss.str().c_str());
                return;
            }
            for (const auto& sgl_ptr : buf_ptr->sgl_list) {
                ulong page = sgl_ptr->page_link  & ~ 0x3;
                physaddr_t paddr = page_to_phy(page) + sgl_ptr->offset;
                size_t len = sgl_ptr->length;
                void* buf = read_memory(paddr, len, "dmabuf",false);
                fwrite(buf, len, 1, dma_file);
                FREEBUF(buf);
            }
            fprintf(fp, "Save dmabuf to file %s !\n", ss.str().c_str());
            fclose(dma_file);
            return;
        }
    }
}

void Dmabuf::print_procs(){
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(5) << "PID" << " "
        << std::left << std::setw(20) << "Comm" << " "
        << std::left << std::setw(8) << "buf_cnt" << " "
        << std::left << "total_size";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& proc_ptr : proc_list) {
        size_t total_size = 0;
        for (const auto& pair : proc_ptr->fd_map) {
            for (const auto& buf_ptr : buf_list) {
                if (pair.first == buf_ptr->addr){
                    total_size += buf_ptr->size;
                }
            }
        }
        std::ostringstream oss;
        oss << std::left << std::setw(5) << proc_ptr->tc->pid << " "
            << std::left << std::setw(20) << proc_ptr->tc->comm << " "
            << std::left << std::setw(8) << proc_ptr->fd_map.size() << " "
            << std::left << csize(total_size);
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Dmabuf::print_proc(ulong pid){
    for (const auto& proc_ptr : proc_list) {
        if (proc_ptr->tc->pid != pid){
            continue;
        }
        for (const auto& pair : proc_ptr->fd_map) {
            for (const auto& buf_ptr : buf_list) {
                if (pair.first == buf_ptr->addr){
                    print_dma_buf(buf_ptr);
                }
            }
        }
    }
}
#pragma GCC diagnostic pop
