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

#include "zraminfo.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

void Zraminfo::cmd_main(void) {

}

Zraminfo::Zraminfo(){
    init_offset();
    if (THIS_KERNEL_VERSION >= LINUX(6,1,0)) {
        ZRAM_FLAG_SHIFT = PAGESHIFT() + 1;
    } else {
        ZRAM_FLAG_SHIFT = 24;
    }
    ZRAM_FLAG_SAME_BIT = 1 << (ZRAM_FLAG_SHIFT + 1);
    ZRAM_FLAG_WB_BIT = 1 << (ZRAM_FLAG_SHIFT + 2);
    ZRAM_COMP_PRIORITY_BIT1 = ZRAM_FLAG_SHIFT + 7;
    ZRAM_COMP_PRIORITY_MASK = 0x3;
    group_cnt = field_size(size_class,fullness_list)/sizeof(struct kernel_list_head);
}

void Zraminfo::init_offset(){
    field_init(zram,table);
    field_init(zram,mem_pool);
    field_init(zram,comp);
    field_init(zram,comps);
    field_init(zram,disk);
    field_init(zram,limit_pages);
    field_init(zram,stats);
    field_init(zram,disksize);
    field_init(zram,compressor);
    field_init(zram,comp_algs);
    field_init(zram,claim);
    struct_init(zram);

    field_init(zs_pool,name);
    field_init(zs_pool,size_class);
    field_init(zs_pool,pages_allocated);
    field_init(zs_pool,stats);
    field_init(zs_pool,isolated_pages);
    field_init(zs_pool,destroying);
    struct_init(zs_pool);

    field_init(size_class,fullness_list);
    field_init(size_class,size);
    field_init(size_class,objs_per_zspage);
    field_init(size_class,pages_per_zspage);
    field_init(size_class,index);
    field_init(size_class,stats);
    struct_init(size_class);

    field_init(zspage,inuse);
    field_init(zspage,freeobj);
    field_init(zspage,first_page);
    field_init(zspage,list);
    field_init(zspage,huge);
    struct_init(zspage);

    field_init(zs_size_stat,objs);

    field_init(zram_stats,compr_data_size);
    field_init(zram_stats,num_reads);
    field_init(zram_stats,num_writes);
    field_init(zram_stats,failed_reads);
    field_init(zram_stats,failed_writes);
    field_init(zram_stats,invalid_io);
    field_init(zram_stats,notify_free);
    field_init(zram_stats,same_pages);
    field_init(zram_stats,huge_pages);
    field_init(zram_stats,huge_pages_since);
    field_init(zram_stats,pages_stored);
    field_init(zram_stats,max_used_pages);
    field_init(zram_stats,writestall);
    field_init(zram_stats,miss_free);
    struct_init(zram_stats);

    field_init(gendisk,disk_name);
    field_init(zcomp,name);
    field_init(link_free,handle);
    field_init(idr, idr_rt);
}

bool Zraminfo::is_zram_enable(){
    if(field_offset(zram,mem_pool) == -1 || field_offset(size_class,size) == -1){
        fprintf(fp, "Please run mod -s zram.ko and zsmalloc.ko at first, then reload the plugins\n");
        return false;
    }
    if (!csymbol_exists("zram_index_idr")){
        fprintf(fp, "zram is disabled\n");
        return false;
    }
    return true;
}

void Zraminfo::parser_zrams(){
    ulong zram_idr_addr = csymbol_value("zram_index_idr");
    if (!is_kvaddr(zram_idr_addr))return;
    ulong xarray_addr = zram_idr_addr + field_offset(idr, idr_rt);
    for (const auto& addr : for_each_xarray(xarray_addr)) {
        parser_zram(addr);
    }
}

bool Zraminfo::read_table_entry(std::shared_ptr<zram> zram_ptr, ulonglong index, struct zram_table_entry* entry){
    ulong table_entry_addr = zram_ptr->table + index * sizeof(zram_table_entry);
    if(!read_struct(table_entry_addr,entry,sizeof(zram_table_entry),"zram_table_entry")){
        fprintf(fp, "read zram_table_entry fail at %lx\n",table_entry_addr);
        return false;
    }
    if(debug)fprintf(fp, "zram_table_entry:%lx, handle:%lx\n",table_entry_addr,entry->handle);
    return true;
}

int Zraminfo::get_class_id(struct zspage& zspage_s){
    int class_idx = 0;
    if (field_offset(zspage, huge) != -1){
        if (THIS_KERNEL_VERSION >= LINUX(6, 6, 0)){
            class_idx = zspage_s.v6_6.class_id;
        }else{
            class_idx = zspage_s.v5_17.class_id;
        }
    }else{
        class_idx = zspage_s.v0.class_id;
    }
    return class_idx;
}

bool Zraminfo::get_zspage(ulong page,struct zspage* zp){
    int zs_magic = 0;
    // find the zspage addr of page
    ulong zspage_addr = read_ulong(page + field_offset(page,private),"page private");
    if (!is_kvaddr(zspage_addr)){
        if(debug)fprintf(fp, "invaild zspage:%lx\n",zspage_addr);
        return false;
    }
    // fprintf(fp, "zspage:%lx\n",zspage_addr);
    if(!read_struct(zspage_addr,zp,sizeof(struct zspage),"zspage")){// read the zspage
        if(debug)fprintf(fp, "read zspage fail at %lx\n",zspage_addr);
        return false;
    }
    if (field_offset(zspage, huge) != -1){
        if (THIS_KERNEL_VERSION >= LINUX(6, 12, 0)){
            zs_magic = zp->v6_12.magic;
        }else if (THIS_KERNEL_VERSION >= LINUX(6, 6, 0)){
            zs_magic = zp->v6_6.magic;
        }else{
            zs_magic = zp->v5_17.magic;
        }
    }else{
        zs_magic = zp->v0.magic;
    }
    if (zs_magic != ZSPAGE_MAGIC) {
        if(debug)fprintf(fp, "zspage magic incorrect: %x\n",zs_magic);
        return false;
    }
    return true;
}

char* Zraminfo::read_object(std::shared_ptr<zram> zram_ptr,struct zram_table_entry entry,int& read_len, bool& huge_obj){
    ulong pfn = 0;
    int obj_idx = 0;
    if (!is_kvaddr(entry.handle)){
        return nullptr;
    }
    ulong handle = read_ulong(entry.handle,"handle");
    handle_to_location(handle,&pfn,&obj_idx);
    if(debug)fprintf(fp, "handle:%lx, pfn:%lx, obj_idx:%d\n",handle,pfn,obj_idx);
    // find the page addr of pfn
    ulong page = pfn_to_page(pfn);
    if (!is_kvaddr(page)){
        if(debug)fprintf(fp, "invaild page:%lx\n",page);
        return nullptr;
    }
    if(debug)fprintf(fp, "page:0x%lx\n",page);
    struct zspage zspage_s;
    if (!get_zspage(page,&zspage_s)){
        if(debug)fprintf(fp, "invaild zspage\n");
        return nullptr;
    }
    int class_idx = get_class_id(zspage_s);
    if(debug)fprintf(fp, "class_idx:%d\n",class_idx);
    // find the size_class to get the obj size by class id
    std::shared_ptr<size_class> class_ptr = zram_ptr->mem_pool->class_list[class_idx];
    size_t obj_size = class_ptr->size;
    if(debug)fprintf(fp, "size_class:%lx\n",class_ptr->addr);
    if(debug)fprintf(fp, "obj size:%zd\n",obj_size);
    char* obj_buf = (char*)std::malloc(obj_size);
    BZERO(obj_buf, obj_size);
    physaddr_t paddr;
    void* tmpbuf;
    size_t offset = (obj_size * obj_idx) & (page_size -1);
    if(debug)fprintf(fp, "obj offset:%zd\n",offset);
    if (offset + obj_size <= page_size){ //in one page
        paddr = page_to_phy(page);
        if (!paddr){
            fprintf(fp, "Can't convert to physaddr of page:%lx\n",page);
            return nullptr;
        }
        if(debug)fprintf(fp, "obj:0x%llx~0x%llx\n",(ulonglong)(paddr + offset),(ulonglong)(paddr + offset + obj_size));
        tmpbuf = read_memory(paddr + offset,obj_size,"zram obj",false);
        memcpy(obj_buf, tmpbuf, obj_size);
        FREEBUF(tmpbuf);
    }else{ //this object is in two pages
        ulong pages[2], sizes[2];
        pages[0] = page;
        if (field_offset(page,freelist) != -1){
            pages[1] = read_pointer(page + field_offset(page,freelist),"page freelist");
        }else{
            pages[1] = read_pointer(page + field_offset(page,index),"page index");
        }
        sizes[0] = page_size - offset;
        sizes[1] = obj_size - sizes[0];
        paddr = page_to_phy(pages[0]);
        if (!paddr){
            fprintf(fp, "Can't convert to physaddr of page:%lx\n",page);
            return nullptr;
        }
        if(debug)fprintf(fp, "obj:0x%llx~0x%llx\n",(ulonglong)(paddr + offset),(ulonglong)(paddr + offset + sizes[0]));
        tmpbuf = read_memory(paddr + offset,sizes[0],"zram obj part0",false);
        memcpy(obj_buf, tmpbuf, sizes[0]);
        FREEBUF(tmpbuf);

        paddr = page_to_phy(pages[1]);
        if (!paddr){
            fprintf(fp, "Can't convert to physaddr of page:%lx\n",page);
            return nullptr;
        }
        if(debug)fprintf(fp, "obj:0x%llx~0x%llx\n",(ulonglong)paddr,(ulonglong)(paddr + sizes[1]));
        tmpbuf = read_memory(paddr,sizes[1],"zram obj part1",false);
        memcpy(obj_buf + sizes[0], tmpbuf, sizes[1]);
        FREEBUF(tmpbuf);
    }
    // Not HugeObject
    if (!(class_ptr->objs_per_zspage == 1 && class_ptr->pages_per_zspage == 1)){
        ulong handle_addr = ULONG(obj_buf);
        // handle addr record in obj has set bit0 as 1, so we need clean it
        handle_addr = handle_addr & ~1;
        if(debug)fprintf(fp, "handle in table:%lx, handle in obj:%lx\n",entry.handle,handle_addr);
        if (entry.handle != handle_addr){
            fprintf(fp, "handle not match\n");
            std::free(obj_buf);
            return nullptr;
        }
        huge_obj = false;
    }else{
        huge_obj = true;
    }
    read_len = obj_size;
    return obj_buf;
}

char* Zraminfo::read_zram_page(ulong zram_addr, ulonglong index){
    if (!is_zram_enable()){
        return nullptr;
    }
    std::shared_ptr<zram> zram_ptr;
    bool is_found = false;
    for (const auto &ptr : zram_list){
        if (ptr->addr == zram_addr){
            is_found = true;
            zram_ptr = ptr;
            break;
        }
    }
    if (is_found == false){
        zram_ptr = parser_zram(zram_addr);
    }
    if (zram_ptr == nullptr){
        fprintf(fp, "Can't found zram %lx\n",zram_addr);
        return nullptr;
    }
    ulonglong total_pages = zram_ptr->disksize >> PAGESHIFT();
    if (index > total_pages){
        if(debug){
            fprintf(fp, "the max index of zram_table_entry:%lld, cur index:%lld\n",total_pages,index);
        }
        return nullptr;
    }
    struct zram_table_entry entry;
    if (!read_table_entry(zram_ptr,index,&entry)){
        return nullptr;
    }
    char* page_data = (char *)GETBUF(page_size);
    BZERO(page_data, page_size);
    if (entry.flags & ZRAM_FLAG_SAME_BIT) { //ZRAM_SAME
        if(debug)fprintf(fp, "ZRAM_SAME page\n");
        unsigned long val = entry.handle ? entry.element : 0;
        memset(page_data, val, page_size / sizeof(unsigned long));
        return page_data;
    }else{
        bool is_huge = false;
        int read_len = 0;
        size_t comp_len = entry.flags & ((1 << ZRAM_FLAG_SHIFT) - 1);
        char *obj_data = read_object(zram_ptr,entry,read_len,is_huge);
        if(debug)fprintf(fp, "ZRAM_FLAG_SHIFT:%d, comp_len:%zd, read_len:%d\n",ZRAM_FLAG_SHIFT,comp_len,read_len);
        if (obj_data == nullptr){
            return nullptr;
        }
        char* data_ptr; 
        // Not HugeObject
        if (is_huge){
            data_ptr = obj_data;
        }else{
            data_ptr = obj_data + ZS_HANDLE_SIZE;
        }
        if (comp_len == page_size) {
            memcpy(page_data, data_ptr, page_size);
        } else {
            std::string compress_name = (zram_ptr->compressor.empty() ? zram_ptr->zcomp_name : zram_ptr->compressor);
            decompress(compress_name, data_ptr, page_data, comp_len, page_size);
        }
        std::free(obj_data);
        return page_data;
    }
}

int Zraminfo::decompress(std::string comp_name,char* source, char* dest,
                                 int compressedSize, int maxDecompressedSize){
    if (comp_name.find("lz4") != std::string::npos){
        try{
            lz4_decompress(source,dest,compressedSize,maxDecompressedSize);
        } catch(const std::exception& e) {
            fprintf(fp, "Exception in zram lz4: %s \n", e.what());
        }
    }else if (comp_name.find("lzo") != std::string::npos){
        try{
            lzo1x_decompress(source,dest,compressedSize,maxDecompressedSize);
        } catch(const std::exception& e) {
            fprintf(fp, "Exception in zram lzo: %s \n", e.what());
        }
    }else{
        fprintf(fp, "Not support %s decompress\n", comp_name.c_str());
    }
    return 0;
}

int Zraminfo::lzo1x_decompress(char *source, char *dest,
                                 int compressedSize, int maxDecompressedSize) {
    size_t tmp_len = maxDecompressedSize;
    return lzo1x_decompress_safe((unsigned char*)source, compressedSize, (unsigned char*)dest, &tmp_len);
}

int Zraminfo::lz4_decompress(char *source, char *dest,
                               int compressedSize, int maxDecompressedSize) {
    return LZ4_decompress_safe((const char *)source, (char *)dest, compressedSize, maxDecompressedSize);
}

void Zraminfo::handle_to_location(ulong handle, ulong* pfn,int* obj_idx){
    handle >>= OBJ_TAG_BITS;
    *pfn = handle >> OBJ_INDEX_BITS;
    *obj_idx = (handle & OBJ_INDEX_MASK);
}

std::shared_ptr<zobj> Zraminfo::parser_obj(int obj_id, ulong handle_addr,physaddr_t start,physaddr_t end){
    std::shared_ptr<zobj> obj_ptr = std::make_shared<zobj>();
    obj_ptr->start = start;
    obj_ptr->end = end;
    obj_ptr->id = obj_id;
    if (handle_addr & OBJ_ALLOCATED_TAG){ //obj is alloc
        obj_ptr->is_free = false;
        obj_ptr->handle_addr = handle_addr & ~OBJ_TAG_BITS; //clean the bit0
        ulong handle = read_ulong(obj_ptr->handle_addr,"obj handle");
        handle_to_location(handle,&obj_ptr->pfn,&obj_ptr->index);
        // fprintf(fp, "       %llx-%llx obj_id:%d,handle_addr:%lx,handle:%lx,pfn:%lx,index:%d alloc\n",(ulonglong)start,(ulonglong)end,obj_id,
        //         handle_addr,handle,obj_ptr->pfn,obj_ptr->index);
    }else{//obj is free
        obj_ptr->is_free = true;
        obj_ptr->handle_addr = handle_addr;
        obj_ptr->next = handle_addr >> OBJ_TAG_BITS;
        // fprintf(fp, "       %llx-%llx obj_id:%d,handle_addr:%ld,next:%d free\n",(ulonglong)start,(ulonglong)end,obj_id,
        //         handle_addr,obj_ptr->next);
    }
    return obj_ptr;
}

void Zraminfo::parser_obj(ulong page_addr,std::shared_ptr<size_class> class_ptr,std::shared_ptr<zpage> zspage_ptr){
    void* buf;
    int offset = read_int(page_addr + field_offset(page,units),"page units");
    physaddr_t page_start = page_to_phy(page_addr);
    physaddr_t page_end = page_start + page_size;
    std::shared_ptr<pageinfo> page_ptr = std::make_shared<pageinfo>();
    page_ptr->addr = page_addr;
    // fprintf(fp, "   Page(%lx):%llx-%llx offset:%d\n", page_addr,(ulonglong)page_start,(ulonglong)page_end,offset);
    ulong handle_addr = 0;
    if (class_ptr->objs_per_zspage == 1 && class_ptr->pages_per_zspage == 1){ // HugeObject
        handle_addr = read_ulong(page_addr + field_offset(page,index),"page index");
        std::shared_ptr<zobj> zsobj = parser_obj(zspage_ptr->obj_index,handle_addr,page_start,page_end);
        page_ptr->obj_list.push_back(zsobj);
        zspage_ptr->obj_index += 1;
    }else{
        // offset of obj in one page
        // ----------------------------------------------------------------
        // |  offset |        obj          |        obj          |        |
        // ----------------------------------------------------------------
        physaddr_t obj_start = page_start + offset;
        physaddr_t obj_end = obj_start + class_ptr->size;
        while (obj_end < page_end){
            buf = read_memory(obj_start + field_offset(link_free,handle),sizeof(unsigned long),"link_free handle",false);
            handle_addr = ULONG(buf);
            FREEBUF(buf);
            std::shared_ptr<zobj> zsobj = parser_obj(zspage_ptr->obj_index,handle_addr,obj_start,obj_end);
            page_ptr->obj_list.push_back(zsobj);
            zspage_ptr->obj_index += 1;
            obj_start = obj_end;
            obj_end += class_ptr->size;
        }
        // part of last obj in one page
        obj_end = page_end;
        buf = read_memory(obj_start + field_offset(link_free,handle),sizeof(unsigned long),"link_free handle",false);
        handle_addr = ULONG(buf);
        FREEBUF(buf);
        std::shared_ptr<zobj> zsobj = parser_obj(zspage_ptr->obj_index,handle_addr,obj_start,obj_end);
        page_ptr->obj_list.push_back(zsobj);
        zspage_ptr->obj_index += 1;
    }
    zspage_ptr->page_list.push_back(page_ptr);
}

void Zraminfo::parser_pages(ulong first_page,std::shared_ptr<size_class> class_ptr,std::shared_ptr<zpage> zspage_ptr){
    ulong page_addr = first_page;
    int page_count = 0;
    while (is_kvaddr(page_addr)){
        parser_obj(page_addr,class_ptr,zspage_ptr);
        page_count += 1;
        if (page_count == class_ptr->pages_per_zspage){
            break;
        }
        page_addr = read_ulong(page_addr + field_offset(page,freelist),"page freelist");
    }
}

std::shared_ptr<zpage> Zraminfo::parser_zpage(ulong addr,std::shared_ptr<size_class> class_ptr){
    if (!is_kvaddr(addr))return nullptr;
    void *zspage_buf = read_struct(addr,"zspage");
    if(zspage_buf == nullptr) return nullptr;
    std::shared_ptr<zpage> zspage_ptr = std::make_shared<zpage>();
    zspage_ptr->addr = addr;
    zspage_ptr->obj_index = 0;
    zspage_ptr->zspage.flag_bits = UINT(zspage_buf);
    zspage_ptr->zspage.inuse = UINT(zspage_buf + field_offset(zspage,inuse));
    zspage_ptr->zspage.freeobj = UINT(zspage_buf + field_offset(zspage,freeobj));
    ulong first_page = ULONG(zspage_buf + field_offset(zspage,first_page));
    FREEBUF(zspage_buf);
    parser_pages(first_page,class_ptr,zspage_ptr);
    return zspage_ptr;
}

std::shared_ptr<size_class> Zraminfo::parser_size_class(ulong addr){
    if (!is_kvaddr(addr))return nullptr;
    void *class_buf = read_struct(addr,"size_class");
    if(class_buf == nullptr) return nullptr;
    std::shared_ptr<size_class> class_ptr = std::make_shared<size_class>();
    class_ptr->addr = addr;
    class_ptr->size = INT(class_buf + field_offset(size_class,size));
    class_ptr->objs_per_zspage = INT(class_buf + field_offset(size_class,objs_per_zspage));
    class_ptr->pages_per_zspage = INT(class_buf + field_offset(size_class,pages_per_zspage));
    class_ptr->index = UINT(class_buf + field_offset(size_class,index));
    class_ptr->zspage_parser = false;
    FREEBUF(class_buf);
    // fprintf(fp, "\nsize_class(%lx) objs_per_zspage:%d size:%d\n", addr,class_ptr->objs_per_zspage,class_ptr->size);
    int stats_cnt = field_size(zs_size_stat,objs)/sizeof(unsigned long);
    ulong stats_addr = addr + field_offset(size_class,stats);
    for (int i = 0; i < stats_cnt; i++){
        class_ptr->stats.push_back(read_ulong(stats_addr + i * sizeof(unsigned long), "size_class_stats"));
    }
    return class_ptr;
}

void Zraminfo::parser_zpage(std::shared_ptr<size_class> class_ptr){
    for (int i = 0; i < group_cnt; i++){
        ulong group_addr = class_ptr->addr + field_offset(size_class,fullness_list) + i * sizeof(struct kernel_list_head);
        int offset = field_offset(zspage,list);
        std::vector<std::shared_ptr<zpage>> zspage_list;
        for (const auto& zspage_addr : for_each_list(group_addr,offset)) {
            zspage_list.push_back(parser_zpage(zspage_addr,class_ptr));
        }
        class_ptr->fullness_list.push_back(zspage_list);
    }
    class_ptr->zspage_parser = true;
}

std::shared_ptr<zs_pool> Zraminfo::parser_mem_pool(ulong addr){
    if (!is_kvaddr(addr)){
        return nullptr;
    }
    void *pool_buf = read_struct(addr,"zs_pool");
    if(pool_buf == nullptr) return nullptr;
    std::shared_ptr<zs_pool> pool_ptr = std::make_shared<zs_pool>();
    pool_ptr->addr = addr;
    pool_ptr->name = read_cstring(ULONG(pool_buf + field_offset(zs_pool,name)),64,"pool_name");
    // fprintf(fp, "zs_pool(%lx) pool_name:%s\n", addr,pool_ptr->name.c_str());
    pool_ptr->pages_allocated = INT(pool_buf + field_offset(zs_pool,pages_allocated));
    if (field_offset(zs_pool,isolated_pages) != -1){
        pool_ptr->isolated_pages = INT(pool_buf + field_offset(zs_pool,isolated_pages));
    }
    if (field_offset(zs_pool,destroying) != -1){
        pool_ptr->destroying = BOOL(pool_buf + field_offset(zs_pool,destroying));
    }
    read_struct(addr + field_offset(zs_pool,stats),&pool_ptr->stats,sizeof(struct zs_pool_stats),"zs_pool_stats");
    int class_cnt = field_size(zs_pool,size_class)/sizeof(void *);
    for (int i = 0; i < class_cnt; i++){
        ulong class_addr = read_pointer(addr + field_offset(zs_pool,size_class) + i * sizeof(void *),"size_class addr");
        if (!is_kvaddr(class_addr))continue;
        pool_ptr->class_list.push_back(parser_size_class(class_addr));
    }
    FREEBUF(pool_buf);
    return pool_ptr;
}

std::shared_ptr<zram> Zraminfo::parser_zram(ulong addr){
    if(debug)fprintf(fp, "zram:%lx \n",addr);
    void *zram_buf = read_struct(addr,"zram");
    if(zram_buf == nullptr) return nullptr;
    ulong pool_addr = ULONG(zram_buf + field_offset(zram,mem_pool));
    if (!is_kvaddr(pool_addr))return nullptr;
    std::shared_ptr<zram> zram_ptr = std::make_shared<zram>();
    zram_ptr->addr = addr;
    zram_ptr->table = ULONG(zram_buf + field_offset(zram,table));
    zram_ptr->mem_pool = parser_mem_pool(ULONG(zram_buf + field_offset(zram,mem_pool)));
    if (field_offset(zram,comp) != -1){
        ulong zcomp_addr = ULONG(zram_buf + field_offset(zram,comp));
        if (is_kvaddr(zcomp_addr)){
            ulong zcomp_name_addr = read_pointer(zcomp_addr + field_offset(zcomp,name),"zcomp_name_addr");
            if (is_kvaddr(zcomp_name_addr)){
                zram_ptr->zcomp_name = read_cstring(zcomp_name_addr,64,"zcomp_name");
            }
        }
    }else if (field_offset(zram,comps) != -1){
        ulong zcomp_addr = ULONG(zram_buf + field_offset(zram,comps));
        if (is_kvaddr(zcomp_addr)){
            ulong zcomp_name_addr = read_pointer(zcomp_addr + field_offset(zcomp,name),"zcomp_name_addr");
            if (is_kvaddr(zcomp_name_addr)){
                zram_ptr->zcomp_name = read_cstring(zcomp_name_addr,64,"zcomp_name");
            }
        }
    }
    ulong disk_name_addr = ULONG(zram_buf + field_offset(zram,disk)) + field_offset(gendisk,disk_name);
    zram_ptr->disk_name = read_cstring(disk_name_addr,32,"disk_name");;
    // fprintf(fp, "disk_name:%s\n", zram_ptr->disk_name.c_str());
    if (field_offset(zram,compressor) != -1){
        char compressor_name[128];
        memcpy(&compressor_name,(void *)zram_buf + field_offset(zram,compressor),128);
        zram_ptr->compressor = extract_string(compressor_name);
        // fprintf(fp, "compressor_name:%s\n", zram_ptr->compressor.c_str());
    }else if (field_offset(zram,comp_algs) != -1){
        ulong name_addr = ULONG(zram_buf + field_offset(zram,comp_algs));
        if (is_kvaddr(name_addr)){
            zram_ptr->compressor = read_cstring(name_addr, 64, "compressor name");
        }
    }
    zram_ptr->limit_pages = ULONG(zram_buf + field_offset(zram,limit_pages));
    zram_ptr->disksize = ULONGLONG(zram_buf + field_offset(zram,disksize));
    zram_ptr->claim = BOOL(zram_buf + field_offset(zram,claim));
    FREEBUF(zram_buf);
    void *stats_buf = read_struct(addr + field_offset(zram,stats),"zram_stats");
    if(stats_buf == nullptr) return nullptr;
    zram_ptr->stats.compr_data_size = ULONGLONG(stats_buf + field_offset(zram_stats,compr_data_size));
    if(field_offset(zram_stats,num_reads) != -1){
        zram_ptr->stats.num_reads = ULONGLONG(stats_buf + field_offset(zram_stats,num_reads));
    }
    if(field_offset(zram_stats,num_writes) != -1){
        zram_ptr->stats.num_writes = ULONGLONG(stats_buf + field_offset(zram_stats,num_writes));
    }
    zram_ptr->stats.failed_reads = ULONGLONG(stats_buf + field_offset(zram_stats,failed_reads));
    zram_ptr->stats.failed_writes = ULONGLONG(stats_buf + field_offset(zram_stats,failed_writes));
    if(field_offset(zram_stats,invalid_io) != -1){
        zram_ptr->stats.invalid_io = ULONGLONG(stats_buf + field_offset(zram_stats,invalid_io));
    }
    zram_ptr->stats.notify_free = ULONGLONG(stats_buf + field_offset(zram_stats,notify_free));
    zram_ptr->stats.same_pages = ULONGLONG(stats_buf + field_offset(zram_stats,same_pages));
    zram_ptr->stats.huge_pages = ULONGLONG(stats_buf + field_offset(zram_stats,huge_pages));
    if(field_offset(zram_stats,huge_pages_since) != -1){
         zram_ptr->stats.huge_pages_since = ULONGLONG(stats_buf + field_offset(zram_stats,huge_pages_since));
    }
    zram_ptr->stats.pages_stored = ULONGLONG(stats_buf + field_offset(zram_stats,pages_stored));
    zram_ptr->stats.max_used_pages = ULONGLONG(stats_buf + field_offset(zram_stats,max_used_pages));
    zram_ptr->stats.writestall = ULONGLONG(stats_buf + field_offset(zram_stats,writestall));
    zram_ptr->stats.miss_free = ULONGLONG(stats_buf + field_offset(zram_stats,miss_free));
    // read_struct(,&zram_ptr->stats,sizeof(struct zram_stats),"zram_stats");
    FREEBUF(stats_buf);
    zram_list.push_back(zram_ptr);
    return zram_ptr;
}

void Zraminfo::enable_debug(bool on){
    debug = true;
}

#pragma GCC diagnostic pop
