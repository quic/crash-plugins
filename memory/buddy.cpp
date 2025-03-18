// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "buddy.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Buddy)
#endif

void Buddy::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "anz:")) != EOF) {
        switch(c) {
            case 'a':
                print_buddy_info();
                break;
            case 'n':
                print_memory_node();
                break;
            case 'z':
                cppString.assign(optarg);
                print_memory_zone(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Buddy::Buddy(){
    field_init(pglist_data,node_zones);
    field_init(pglist_data,node_start_pfn);
    field_init(pglist_data,node_present_pages);
    field_init(pglist_data,node_spanned_pages);
    field_init(pglist_data,node_id);
    field_init(pglist_data,totalreserve_pages);
    field_init(pglist_data,vm_stat);

    field_init(zone,_watermark);
    field_init(zone,watermark_boost);
    field_init(zone,lowmem_reserve);
    field_init(zone,zone_start_pfn);
    field_init(zone,managed_pages);
    field_init(zone,spanned_pages);
    field_init(zone,present_pages);
    field_init(zone,cma_pages);
    field_init(zone,name);
    field_init(zone,free_area);
    field_init(zone,vm_stat);
    field_init(free_area,free_list);
    field_init(free_area,nr_free);
    field_init(page,buddy_list);
    field_init(page,lru);
    struct_init(pglist_data);
    struct_init(zone);
    struct_init(free_area);
    struct_init(atomic_long_t);
    cmd_name = "buddy";
    help_str_list={
        "buddy",                            /* command name */
        "dump buddy information",        /* short description */
        "-a \n"
            "  buddy -n\n"
            "  buddy -z <zone addr>\n"
            "  This command dumps the buddy info.",
        "\n",
        "EXAMPLES",
        "\n",
        "  Display buddy info:",
        "   %s> buddy -a",
        "       Node(0)",
        "       ---------------------------------------------------------------------------------------------------------------------------",
        "                                                         zone DMA32",
        "       ---------------------------------------------------------------------------------------------------------------------------",
        "             Order       4K       8K      16K      32K      64K     128K     256K     512K    1024K    2048K    4096K      Total",
        "         Unmovable     1645     2367      958      712       37       11        2        0        0        0        0    66.32Mb",
        "           Movable     5496     3435     1998      764      145       33        5        0        0        0        0   117.84Mb",
        "       Reclaimable      135       39       94       56        0        0        0        0        0        0        0     4.05Mb",
        "               CMA        0        0        0        0        0        0        0        0        0        0        0         0b",
        "        HighAtomic      109       31       25       17        1        1        0        0        0        0        0     1.78Mb",
        "           Isolate        0        0        0        0        0        0        0        0        0        0        0         0b",
        "             Total  28.85Mb  45.88Mb  48.05Mb  48.41Mb  11.44Mb   5.62Mb   1.75Mb       0b       0b       0b       0b   189.99Mb",
        "       ---------------------------------------------------------------------------------------------------------------------------",
        "\n",
        "  Display memory node info:",
        "   %s> buddy -n",
        "    Config:",
        "    ---------------------------------------",
        "    min_free_kbytes          : 5792kb",
        "    user_min_free_kbytes     : 5792kb",
        "    watermark_scale_factor   : 150",
        "    ---------------------------------------",
        "    ",
        "    Node:",
        "    =======================================",
        "    pglist_data(0) : 0xffffffde3102c340",
        "       spanned        : 524288(2.00Gb)",
        "       present        : 519680(1.98Gb)",
        "       hole           : 4608(18.00Mb)",
        "       start_pfn      : 40000",
        "       start_paddr    : 0x40000000",
        "    ",
        "      DMA32 zone: 0xffffffde3102c340",
        "         spanned           : 524288(2.00Gb)",
        "         present           : 519680(1.98Gb)",
        "         hole              : 4608(18.00Mb)",
        "         managed           : 455177(1.74Gb)",
        "         reserved          : 64503(251.96Mb)",
        "         cma_pages         : 67584(264.00Mb)",
        "         start_pfn         : 40000",
        "         start_paddr       : 0x40000000",
        "         watermark_boost   : 0",
        "         WMARK_HIGH        : 15102(58.99Mb)",
        "         WMARK_LOW         : 8275(32.32Mb)",
        "         WMARK_MIN         : 1448(5.66Mb)",
        "\n",
        "  Display page info of zone:",
        "   %s> buddy -z 0xffffffde3102c340",
        "    Order[0] 4K",
        "       migratetype:Unmovable Order[0]",
        "           [1]Page:0xfffffffe0152bfc0 PA:0x94aff000",
        "           [2]Page:0xfffffffe0152c380 PA:0x94b0e000",
        "\n",
    };
    initialize();
    parser_buddy_info();
}

std::vector<std::vector<ulong>> Buddy::parser_free_list(ulong addr){
    // fprintf(fp, "   free_list:%lx\n", addr);
    std::vector<std::vector<ulong>> free_list;
    int free_list_cnt = field_size(free_area,free_list)/struct_size(list_head);
    for (size_t i = 0; i < free_list_cnt; i++){
        ulong list_head_addr = addr + i * struct_size(list_head);
        if (!is_kvaddr(list_head_addr))continue;
        int offset = 0;
        if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
            offset = field_offset(page,buddy_list);
        }else{
            offset = field_offset(page,lru);
        }
        std::vector<ulong> page_list = for_each_list(list_head_addr,offset);
        free_list.push_back(page_list);
    }
    return free_list;
}

std::vector<std::shared_ptr<free_area>> Buddy::parser_free_area(ulong addr){
    // fprintf(fp, "free_area:%lx\n", addr);
    std::vector<std::shared_ptr<free_area>> area_list;
    int free_area_cnt = field_size(zone,free_area)/struct_size(free_area);
    for (size_t i = 0; i < free_area_cnt; i++){
        ulong area_addr = addr + field_offset(zone,free_area) + i * struct_size(free_area);
        void *area_buf = read_struct(area_addr,"free_area");
        if(area_buf == nullptr) continue;
        std::shared_ptr<free_area> area_ptr = std::make_shared<free_area>();
        area_ptr->addr = area_addr;
        area_ptr->nr_free = ULONG(area_buf + field_offset(free_area,nr_free));
        area_ptr->free_list = parser_free_list(addr + field_offset(free_area,free_list) + i * struct_size(free_area));
        area_list.push_back(area_ptr);
        FREEBUF(area_buf);
    }
    return area_list;
}

std::shared_ptr<pglist_data> Buddy::parser_node_info(ulong addr){
    // fprintf(fp, "pglist_data:%lx\n", addr);
    void *node_buf = read_struct(addr,"pglist_data");
    if(node_buf == nullptr) return nullptr;
    std::shared_ptr<pglist_data> node_ptr = std::make_shared<pglist_data>();
    node_ptr->id = INT(node_buf + field_offset(pglist_data,node_id));
    node_ptr->addr = addr;
    node_ptr->start_pfn = ULONG(node_buf + field_offset(pglist_data,node_start_pfn));
    node_ptr->present_pages = ULONG(node_buf + field_offset(pglist_data,node_present_pages));
    node_ptr->spanned_pages = ULONG(node_buf + field_offset(pglist_data,node_spanned_pages));
    node_ptr->totalreserve_pages = ULONG(node_buf + field_offset(pglist_data,totalreserve_pages));
    int vm_stat_cnt = field_size(pglist_data,vm_stat)/struct_size(atomic_long_t);
    for (size_t i = 0; i < vm_stat_cnt; i++){
        node_ptr->vm_stat.push_back(ULONG(node_buf + field_offset(pglist_data,vm_stat) + i * struct_size(atomic_long_t)));
    }
    ulong node_zones = addr + field_offset(pglist_data,node_zones);
    for (size_t i = 0; i < vt->nr_zones; i++) {
        ulong zone_addr = (node_zones + (i * struct_size(zone)));
        std::shared_ptr<zone> zone_ptr = parser_zone_info(zone_addr);
        if (zone_ptr == nullptr) continue;
        node_ptr->zone_list.push_back(zone_ptr);
    }
    FREEBUF(node_buf);
    return node_ptr;
}

std::shared_ptr<zone> Buddy::parser_zone_info(ulong addr){
    // fprintf(fp, "zone:%lx\n", addr);
    void *zone_buf = read_struct(addr,"zone");
    if(zone_buf == nullptr) return nullptr;
    std::shared_ptr<zone> zone_ptr = std::make_shared<zone>();
    zone_ptr->addr = addr;
    zone_ptr->start_pfn = ULONG(zone_buf + field_offset(zone,zone_start_pfn));
    zone_ptr->present_pages = ULONG(zone_buf + field_offset(zone,present_pages));
    zone_ptr->spanned_pages = ULONG(zone_buf + field_offset(zone,spanned_pages));
    zone_ptr->managed_pages = ULONG(zone_buf + field_offset(zone,managed_pages));
    if (field_offset(zone,cma_pages) > 0){
        zone_ptr->cma_pages = ULONG(zone_buf + field_offset(zone,cma_pages));
    }
    zone_ptr->name = read_cstring(ULONG(zone_buf + field_offset(zone,name)),64, "zone_name");
    zone_ptr->watermark_boost = ULONG(zone_buf + field_offset(zone,watermark_boost));
    for (size_t i = 0; i < 3; i++){
        int offset = field_offset(zone,_watermark);
        int long_size = sizeof(long);
        int waddr = offset + (i * long_size);
        zone_ptr->_watermark[i] = ULONG(zone_buf + (field_offset(zone,_watermark) + i * sizeof(unsigned long)));
        zone_ptr->lowmem_reserve[i] = ULONG(zone_buf + field_offset(zone,lowmem_reserve) + i * sizeof(long));
    }
    int vm_stat_cnt = field_size(zone,vm_stat)/struct_size(atomic_long_t);
    for (size_t i = 0; i < vm_stat_cnt; i++){
        zone_ptr->vm_stat.push_back(ULONG(zone_buf + field_offset(zone,vm_stat) + i * struct_size(atomic_long_t)));
    }
    zone_ptr->free_areas = parser_free_area(addr + field_offset(zone,free_area));
    FREEBUF(zone_buf);
    return zone_ptr;
}

void Buddy::get_migratetype_names(){
    int migratetype_cnt = get_array_length(TO_CONST_STRING("migratetype_names"),nullptr, 0);
    ulong migratetype_names_addr = csymbol_value("migratetype_names");
    for (size_t i = 0; i < migratetype_cnt; i++){
        ulong addr = migratetype_names_addr + i * sizeof(void *);
        if (!is_kvaddr(addr))continue;
        addr = read_pointer(addr,"migratetype_names addr");
        migratetype_names.push_back(read_cstring(addr,64,"migratetype_names"));
    }
}

void Buddy::parser_buddy_info(){
    struct node_table *nt;
    if (!(vt->flags & (NODES|ZONES)))
        fprintf(fp, "dump_pgtype_info called without (NODES|ZONES)\n");
    if (!struct_size(zone)){
        fprintf(fp, "zone not found in this kernel\n");
        return;
    }
    if (!struct_size(free_area)) {
        fprintf(fp, "free_area not found in this kernel\n");
        return;
    }
    if (!csymbol_exists("migratetype_names") || (get_symbol_type(TO_CONST_STRING("migratetype_names"),nullptr, nullptr) != TYPE_CODE_ARRAY)) {
        fprintf(fp, "migratetype_names not found in this kernel\n");
        return;
    }
    for (size_t n = 0; n < vt->numnodes; n++) {
        nt = &vt->node_table[n];
        std::shared_ptr<pglist_data> node_ptr = parser_node_info(nt->pgdat);
        if(node_ptr == nullptr) continue;
        node_list.push_back(node_ptr);
    }
    get_migratetype_names();
    if (csymbol_exists("min_free_kbytes")){
        min_free_kbytes = read_int(csymbol_value("min_free_kbytes"),"min_free_kbytes");
    }
    if (csymbol_exists("user_min_free_kbytes")){
        user_min_free_kbytes = read_int(csymbol_value("user_min_free_kbytes"),"user_min_free_kbytes");
    }
    if (csymbol_exists("watermark_scale_factor")){
        watermark_scale_factor = read_int(csymbol_value("watermark_scale_factor"),"watermark_scale_factor");
    }
}

void Buddy::print_buddy_info(){
    fprintf(fp, "\n");
    for (const auto& node_ptr : node_list) {
        fprintf(fp, "Node(%d) \n", node_ptr->id);
        for (const auto& zone_ptr : node_ptr->zone_list) {
            if(zone_ptr->managed_pages == 0 || zone_ptr->spanned_pages == 0 || zone_ptr->present_pages == 0){
                continue;
            }
            fprintf(fp, "---------------------------------------------------------------------------------------------------------------------------\n");
            fprintf(fp, "                                             zone %s \n", zone_ptr->name.c_str());
            fprintf(fp, "---------------------------------------------------------------------------------------------------------------------------\n");
            fprintf(fp, "%12s ", "Order");
            for (int o = 0; o < vt->nr_free_areas; o++) { //order
                fprintf(fp, "%8s ", csize((1U << o)*page_size).c_str());
            }
            fprintf(fp, "%10s\n", "Total");
            int free_list_cnt = field_size(free_area,free_list)/struct_size(list_head);
            if (free_list_cnt > migratetype_names.size()){
                free_list_cnt = migratetype_names.size();
            }
            size_t total_size = 0;
            size_t total_by_order[vt->nr_free_areas] = {0};
            for (int m = 0; m < free_list_cnt; m++) { //migrate type
                fprintf(fp, "%12s ", migratetype_names[m].c_str());
                size_t total_per_type = 0;
                for (int o = 0; o < vt->nr_free_areas; o++) { //order
                    int free_cnt = zone_ptr->free_areas[o]->free_list[m].size();
                    fprintf(fp, "%8d ", free_cnt);
                    size_t per_size = power(2, o) * page_size;
                    total_per_type +=  (per_size * free_cnt);
                    total_by_order[o] += (per_size * free_cnt);
                }
                total_size += total_per_type;
                fprintf(fp, "%10s\n", csize(total_per_type).c_str());
            }
            fprintf(fp, "%12s ", "Total");
            for (int o = 0; o < vt->nr_free_areas; o++) { //order
                fprintf(fp, "%8s ", csize(total_by_order[o]).c_str());
            }
            fprintf(fp, "%10s\n", csize(total_size).c_str());
            fprintf(fp, "---------------------------------------------------------------------------------------------------------------------------\n\n\n");
        }
        fprintf(fp, "\n");
    }
}

void Buddy::print_node_info(std::shared_ptr<pglist_data> node_ptr){
    int len = 15;
    ulong spanned_size = node_ptr->spanned_pages*page_size;
    ulong present_size = node_ptr->present_pages*page_size;
    ulong hole_size = spanned_size - present_size;
    std::ostringstream oss;
    oss << std::left << "pglist_data(" << node_ptr->id << ")" << ": " << std::hex << node_ptr->addr;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "  spanned" << ": "
        << std::dec << node_ptr->spanned_pages << "(" << csize(spanned_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "  present" << ": "
        << std::dec << node_ptr->present_pages << "(" << csize(present_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "  hole" << ": "
        << std::dec << (node_ptr->spanned_pages - node_ptr->present_pages) << "(" << csize(hole_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "  start_pfn" << ": "
        << std::hex << node_ptr->start_pfn;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "  start_paddr" << ": "
        << std::hex << (node_ptr->start_pfn << 12);
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");
}

void Buddy::print_zone_info(std::shared_ptr<zone> zone_ptr){
    std::ostringstream oss;
    oss << std::left << "  " << zone_ptr->name << " zone:" << std::hex << zone_ptr->addr;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    spanned" << ": "
        << std::dec << zone_ptr->spanned_pages << "(" << csize(zone_ptr->spanned_pages*page_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    present" << ": "
        << std::dec << zone_ptr->present_pages << "(" << csize(zone_ptr->present_pages*page_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    hole" << ": "
        << std::dec << (zone_ptr->spanned_pages - zone_ptr->present_pages) << "("
        << csize((zone_ptr->spanned_pages - zone_ptr->present_pages)*page_size)
        << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    managed" << ": "
        << std::dec << zone_ptr->managed_pages << "(" << csize(zone_ptr->managed_pages*page_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    reserved" << ": "
        << std::dec << (zone_ptr->present_pages - zone_ptr->managed_pages) << "("
        << csize((zone_ptr->present_pages - zone_ptr->managed_pages)*page_size)
        << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    if (field_offset(zone,cma_pages) > 0){
        oss << std::left << std::setw(20) << "    cma_pages" << ": "
            << std::dec << zone_ptr->cma_pages << "(" << csize(zone_ptr->cma_pages*page_size) << ")";
        fprintf(fp, "%s \n",oss.str().c_str());
        oss.str("");
    }
    oss << std::left << std::setw(20) << "    start_pfn" << ": "
        << std::hex << zone_ptr->start_pfn;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    start_paddr" << ": "
        << std::hex << (zone_ptr->start_pfn << 12);
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");


    if (field_offset(zone,watermark_boost) > 0){
        oss << std::left << std::setw(20) << "    watermark_boost" << ": "
            << std::dec << zone_ptr->watermark_boost;
        fprintf(fp, "%s \n",oss.str().c_str());
        oss.str("");
    }
    oss << std::left << std::setw(20) << "    WMARK_HIGH" << ": "
        << std::dec << zone_ptr->_watermark[zone_watermarks::WMARK_HIGH]
        << "(" << csize(zone_ptr->_watermark[zone_watermarks::WMARK_HIGH]*page_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    WMARK_LOW" << ": "
        << std::dec << zone_ptr->_watermark[zone_watermarks::WMARK_LOW]
        << "(" << csize(zone_ptr->_watermark[zone_watermarks::WMARK_LOW]*page_size) << ")";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "    WMARK_MIN" << ": "
        << std::dec << zone_ptr->_watermark[zone_watermarks::WMARK_MIN]
        << "(" << csize(zone_ptr->_watermark[zone_watermarks::WMARK_MIN]*page_size) << ")";
        fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");
}

void Buddy::print_memory_zone(std::string addr){
    unsigned long number = std::stoul(addr, nullptr, 16);
    if (number <= 0){
        return;
    }
    for (const auto& node_ptr : node_list) {
        for (const auto& zone_ptr : node_ptr->zone_list) {
            if (zone_ptr->addr != number) {
                continue;
            }
            for (size_t o = 0; o < zone_ptr->free_areas.size(); o++){
                std::shared_ptr<free_area> area_ptr = zone_ptr->free_areas[o];
                fprintf(fp, "\nOrder[%zu] %s\n", o, csize((1U << o)*page_size).c_str());
                int free_list_cnt = area_ptr->free_list.size();
                if (free_list_cnt > migratetype_names.size()){
                    free_list_cnt = migratetype_names.size();
                }
                for (size_t m = 0; m < free_list_cnt; m++){
                    std::vector<ulong> page_list = area_ptr->free_list[m];
                    if (page_list.size() > 0){
                        fprintf(fp, "   migratetype:%s Order[%zu]\n", migratetype_names[m].c_str(),o);
                    }
                    int index = 1;
                    for (const auto& page_addr : page_list) {
                        physaddr_t paddr = page_to_phy(page_addr);
                        std::ostringstream oss;
                        oss << "     [" << std::setw(5) << std::setfill('0') << index << "]"
                            << "Page:" << std::hex << page_addr << " "
                            << "PA:" << paddr;
                        fprintf(fp, "%s \n",oss.str().c_str());
                        index += 1;
                    }
                }
            }
        }
    }
}

void Buddy::print_memory_node(){
    char buf[BUFSIZE];
    fprintf(fp, "\nConfig:\n");
    fprintf(fp, "---------------------------------------\n");
    std::ostringstream oss;
    oss << std::left << std::setw(25) << "min_free_kbytes" << ": "
        << min_free_kbytes << "kB";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(25) << "user_min_free_kbytes" << ": "
        << user_min_free_kbytes << "kB";
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(25) << "watermark_scale_factor" << ": "
        << watermark_scale_factor;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");
    fprintf(fp, "---------------------------------------\n\n");
    fprintf(fp, "Node:\n");
    for (const auto& node_ptr : node_list) {
        fprintf(fp, "=======================================\n");
        print_node_info(node_ptr);
        fprintf(fp, "\n");
        for (const auto& zone_ptr : node_ptr->zone_list) {
            if(zone_ptr->managed_pages == 0 || zone_ptr->spanned_pages == 0 || zone_ptr->present_pages == 0){
                continue;
            }
            print_zone_info(zone_ptr);
            fprintf(fp, "\n");
        }
    }
}
#pragma GCC diagnostic pop
