// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "dmabuf.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Dmabuf)
#endif

void Dmabuf::cmd_main(void) {
    int c;
    int flags;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (buf_list.size() == 0){
        parser_dma_bufs();
    }
    while ((c = getopt(argcnt, args, "abd:")) != EOF) {
        switch(c) {
            case 'a':
                flags = SHOW_DMA_BUF | SHOW_ATTACH;
                print_dma_buf_list(flags);
                break;
            case 'b':
                flags = SHOW_DMA_BUF;
                print_dma_buf_list(flags);
                break;
            case 'd':
                cppString.assign(optarg);
                print_dma_buf(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
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
    field_init(module,name);
    field_init(device,kobj);
    field_init(device,driver);
    field_init(kobject,name);
    field_init(device_driver,name);
    field_init(file,f_count);

    struct_init(dma_buf);
    struct_init(dma_buf_attachment);
    struct_init(device);
    struct_init(device_driver);
    // print_table();
    cmd_name = "dmabuf";
    help_str_list={
        "dmabuf",                            /* command name */
        "dump dmabuf information",        /* short description */
        "-a \n"
            "  dmabuf -b\n"
            "  dmabuf -d <dmabuf addr>\n"
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

void Dmabuf::parser_dma_bufs(){
    if (!csymbol_exists("db_list")){
        fprintf(fp, "db_list doesn't exist in this kernel!\n");
        return;
    }
    ulong db_list_addr = csymbol_value("db_list");
    if (!is_kvaddr(db_list_addr))return;
    int offset = field_offset(dma_buf,list_node);
    std::vector<ulong> db_list = for_each_list(db_list_addr,offset);
    for (const auto& buf_addr : db_list) {
        void *buf = read_struct(buf_addr,"dma_buf");
        if(buf == nullptr) continue;
        std::shared_ptr<dma_buf> buf_ptr = std::make_shared<dma_buf>();
        buf_ptr->addr = buf_addr;
        buf_ptr->size = INT(buf + field_offset(dma_buf,size));
        buf_ptr->priv = ULONG(buf + field_offset(dma_buf,priv));
        buf_ptr->file = ULONG(buf + field_offset(dma_buf,file));
        if (is_kvaddr(buf_ptr->file)){
            buf_ptr->f_count = read_long(buf_ptr->file + field_offset(file,f_count),"file_f_count");
        }
        ulong name_addr = ULONG(buf + field_offset(dma_buf,name));
        if (is_kvaddr(name_addr)){
             buf_ptr->name = read_cstring(name_addr,64,"dma_buf_name");
        }
        name_addr = ULONG(buf + field_offset(dma_buf,exp_name));
        if (is_kvaddr(name_addr)){
             buf_ptr->exp_name = read_cstring(name_addr,64,"dma_buf_exp_name");
        }
        ulong ops_addr = ULONG(buf + field_offset(dma_buf,ops));
        struct syment *sp;
        ulong offset;
        if (sp = value_search(ops_addr, &offset)) {
            buf_ptr->ops_name = sp->name;
        }
        FREEBUF(buf);
        ulong attachments_head = buf_addr + field_offset(dma_buf,attachments);
        buf_ptr->attachments = parser_dma_buf_attachment(attachments_head);
        buf_list.push_back(buf_ptr);
    }
}

std::vector<std::shared_ptr<dma_buf_attachment>> Dmabuf::parser_dma_buf_attachment(ulong list_head){
    std::vector<std::shared_ptr<dma_buf_attachment>> res;
    int offset = field_offset(dma_buf_attachment,node);
    std::vector<ulong> attach_list = for_each_list(list_head,offset);
    for (const auto& attach_addr : attach_list) {
        void *buf = read_struct(attach_addr,"dma_buf_attachment");
        if(buf == nullptr) continue;
        std::shared_ptr<dma_buf_attachment> attach_ptr = std::make_shared<dma_buf_attachment>();
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

void Dmabuf::print_dma_buf_list(int flag){
    int index = 1;
    int total_size = 0;
    std::unordered_map<std::string, ulong> size_map;
    std::sort(buf_list.begin(), buf_list.end(),[&](const std::shared_ptr<dma_buf>& a, const std::shared_ptr<dma_buf>& b){
        return a->size > b->size;
    });
    fprintf(fp, "=======================================================================================\n");
    for (const auto& dma_buf : buf_list) {
        total_size += dma_buf->size;
        auto it = size_map.find(dma_buf->exp_name);
        if (it != size_map.end()) {
            it->second += dma_buf->size;
        } else {
            size_map[dma_buf->exp_name] = dma_buf->size;
        }
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
        if (flag & SHOW_ATTACH){
            for (const auto& attach : dma_buf->attachments) {
                std::ostringstream oss_a;
                oss_a << "        dma_buf_attachment:" << std::hex <<  std::setfill(' ') << attach->addr << " "
                    << "dir:"  << std::left << directions[attach->dir] << " "
                    << "priv:" << std::left << std::hex << attach->priv << " "
                    << "device:[" << std::left << attach->device_name << "] "
                    << "driver:[" << std::left << attach->driver_name << "]";
                fprintf(fp, "%s \n",oss_a.str().c_str());
            }
            fprintf(fp, "\n");
        }
    }
    fprintf(fp, "=======================================================================================\n");
    fprintf(fp, "Total size:%s\n",csize(total_size).c_str());
    for (auto& pair : size_map) {
        fprintf(fp, " [%s]:%s",pair.first.c_str(),csize(pair.second).c_str());
    }
    fprintf(fp, " \n");
}

void Dmabuf::print_dma_buf(std::string addr){
    unsigned long number = std::stoul(addr, nullptr, 16);
    if (number <= 0){
        return;
    }
    for (const auto& dma_buf : buf_list) {
        if (dma_buf->addr == number) {
            fprintf(fp, "\n========================================================================\n");
            std::ostringstream oss;
            oss << std::left << std::setw(10) << "dma_buf" << ": "
                << std::hex << dma_buf->addr;
            fprintf(fp, "%s \n",oss.str().c_str());
            oss.str("");

            oss << std::left << std::setw(10) << "exp_name" << ": "
                << dma_buf->exp_name;
            fprintf(fp, "%s \n",oss.str().c_str());
            oss.str("");

            oss << std::left << std::setw(10) << "ops" << ": "
                << dma_buf->ops_name;
            fprintf(fp, "%s \n",oss.str().c_str());
            oss.str("");

            oss << std::left << std::setw(10) << "size" << ": "
                << csize(dma_buf->size);
            fprintf(fp, "%s \n",oss.str().c_str());
            oss.str("");

            oss << std::left << std::setw(10) << "sg_buffer" << ": "
                << std::hex << dma_buf->priv;
            fprintf(fp, "%s \n",oss.str().c_str());
            oss.str("");
            fprintf(fp, "========================================================================\n");
            for (const auto& attach : dma_buf->attachments) {
                std::ostringstream oss_a;
                oss_a << "    dma_buf_attachment:" << std::hex <<  std::setfill(' ') << attach->addr << " "
                    << "dir:"  << std::left << directions[attach->dir] << " "
                    << "priv:" << std::left << std::hex << attach->priv << " "
                    << "device:[" << std::left << attach->device_name << "] "
                    << "driver:[" << std::left << attach->driver_name << "]";
                fprintf(fp, "%s \n",oss_a.str().c_str());
            }
            fprintf(fp, "\n");
        }
    }
}
#pragma GCC diagnostic pop
