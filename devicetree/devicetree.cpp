// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "devicetree.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Devicetree::Devicetree(){
    field_init(device_node,name);
    field_init(device_node,phandle);
    field_init(device_node,full_name);
    field_init(device_node,fwnode);
    field_init(device_node,properties);
    field_init(device_node,parent);
    field_init(device_node,child);
    field_init(device_node,sibling);
    field_init(property,name);
    field_init(property,length);
    field_init(property,value);
    field_init(property,next);

    struct_init(device_node);
    struct_init(property);

    if (!csymbol_exists("of_root")){
        LOGE( "of_root doesn't exist in this kernel!\n");
        return;
    }
    ulong of_root_addr = csymbol_value("of_root");
    if (!is_kvaddr(of_root_addr)) return;
    root_addr = read_pointer(of_root_addr,"of_root");
    root_node = read_node("", root_addr);
}

void Devicetree::cmd_main(void) {
    // TODO
}

std::shared_ptr<Property> Devicetree::getprop(ulong node_addr,const std::string& name){
    std::shared_ptr<device_node> node_ptr = find_node_by_addr(node_addr);
    if(node_ptr == nullptr) return nullptr;
    for (auto it = node_ptr->props.begin(); it != node_ptr->props.end(); ++it) {
        std::shared_ptr<Property> prop = *it;
        if(prop->name == name){
            return prop;
        }
    }
    return nullptr;
}

std::shared_ptr<device_node> Devicetree::read_node(const std::string& path, ulong node_addr){
    if (!is_kvaddr(node_addr)) return nullptr;
    void *node_buf = read_struct(node_addr,"device_node");
    if(node_buf == nullptr) return nullptr;
    std::shared_ptr<device_node> node_ptr = std::make_shared<device_node>();
    node_ptr->addr = node_addr;

    ulong full_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
    std::string full_name = read_cstring(full_name_addr,64, "device_node_full_name");
    std::string node_path;
    if(node_addr == root_addr){
        full_name = "/";
        node_path = full_name;
    }else{
        node_path = path + "/" + full_name;
    }
    node_ptr->full_name = full_name;
    std::string temstr = node_path;
    if (temstr.size() >= 2 && temstr[0] == '/' && temstr[1] == '/') {
        node_ptr->node_path = temstr.substr(1);
    }
    ulong name_addr = ULONG(node_buf + field_offset(device_node,name));
    node_ptr->name = read_cstring(name_addr,64, "device_node name");
    // fprintf(fp, "addr:0x%lx, name:%s,full_name:%s,node_path:%s\n",node_addr,
    //     node_ptr->name.c_str(),
    //     node_ptr->full_name.c_str(),
    //     node_ptr->node_path.c_str());
    ulong prop_addr = ULONG(node_buf + field_offset(device_node,properties));
    if (is_kvaddr(prop_addr)){
        std::vector<std::shared_ptr<Property>> props = read_propertys(prop_addr);
        node_ptr->props = props;
    }
    ulong child = ULONG(node_buf + field_offset(device_node,child));
    if (is_kvaddr(child)){
        node_ptr->child = read_node(node_path,child);
    }
    ulong sibling = ULONG(node_buf + field_offset(device_node,sibling));
    if (is_kvaddr(sibling)){
        node_ptr->sibling = read_node(path,sibling);
    }
    node_addr_maps[node_addr] = node_ptr;
    node_path_maps[node_path] = node_ptr;
    FREEBUF(node_buf);
    return node_ptr;
}

std::vector<std::shared_ptr<Property>> Devicetree::read_propertys(ulong addr){
    std::vector<std::shared_ptr<Property>> res;
    while (is_kvaddr(addr))
    {
        std::shared_ptr<Property> prop = std::make_shared<Property>();
        prop->addr = addr;
        void *prop_buf = read_struct(addr,"property");
        if(prop_buf == nullptr) return res;
        ulong name_addr = ULONG(prop_buf + field_offset(property,name));
        prop->name = read_cstring(name_addr,64,"property_name");
        int length = UINT(prop_buf + field_offset(property,length));
        prop->length = length;
        ulong value_addr = ULONG(prop_buf + field_offset(property,value));
        if(length > 0){
            prop->value = malloc(length);
            void *prop_val = read_memory(value_addr,length,"property_value");
            memcpy(prop->value, prop_val, length);
            FREEBUF(prop_val);
        }
        res.push_back(prop);
        addr = ULONG(prop_buf + field_offset(property,next));
        FREEBUF(prop_buf);
    }
    return res;
}

std::vector<DdrRange> Devicetree::get_ddr_size(){
    std::vector<DdrRange> res;
    std::vector<std::shared_ptr<device_node>> nodes = find_node_by_name("/memory");
    if (nodes.size() == 0)
        return res;
    std::shared_ptr<Property> prop = getprop(nodes[0]->addr,"device_type");
    std::string tempstr;
    tempstr.assign((char *)prop->value);
    if (tempstr != "memory"){
        return res;
    }
    // read property of reg
    //       <|  start     | |   size     |
    // reg = <0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000>
    prop = getprop(nodes[0]->addr,"reg");
    res = parse_memory_regs(prop);
    return res;
}

std::vector<DdrRange> Devicetree::parse_memory_regs(std::shared_ptr<Property> prop){
    std::vector<DdrRange> result;
    char* ptr = reinterpret_cast<char*>(prop->value);
    // prop->length how many byte of this prop val
    uint32_t reg_cnt = prop->length / 4;
    uint32_t regs[reg_cnt];
    for (uint32_t i = 0; i < reg_cnt; ++i) {
        regs[i] = ntohl(UINT(ptr + i * sizeof(int)));
    }
    int group_cnt = reg_cnt / 4;
    for (uint32_t i = 0; i < group_cnt; ++i) {
        size_t address = static_cast<size_t>((static_cast<uint64_t>(regs[i * 4 + 0]) << 32) | regs[i * 4 + 1]);
        size_t size = static_cast<size_t>((static_cast<uint64_t>(regs[i * 4 + 2]) << 32) | regs[i * 4 + 3]);
        result.push_back({address, size});
    }
    return result;
}

std::vector<std::shared_ptr<device_node>> Devicetree::find_node_by_name(const std::string& name){
    std::string node_path;
    std::shared_ptr<device_node> node_ptr;
    std::vector<std::shared_ptr<device_node>> res;
    for (const auto& node_item : node_path_maps) {
        node_path = node_item.first;
        node_ptr = node_item.second;
        size_t pos = node_path.find_last_of(name);
        if (pos == std::string::npos) continue;
        if(node_ptr->full_name == name || node_ptr->name == name || node_ptr->node_path == name){
            res.push_back(node_ptr);
        }
    }
    return res;
}

std::shared_ptr<device_node> Devicetree::find_node_by_addr(ulong addr){
    for (const auto& node_item : node_addr_maps) {
        if(node_item.first == addr){
            return node_item.second;
        }
    }
    return nullptr;
}

bool Devicetree::is_str_prop(const std::string& name) {
    for (const auto& str : str_props) {
        if (name.find(str) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool Devicetree::is_int_prop(const std::string& name) {
    for (const auto& str : int_props) {
        if (name.find(str) != std::string::npos) {
            return true;
        }
    }
    return false;
}

#pragma GCC diagnostic pop