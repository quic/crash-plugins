// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "memblock.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Memblock)
#endif

void Memblock::cmd_main(void) {
    int c;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "a")) != EOF) {
	    switch(c) {
		    case 'a':
			    print_memblock();
			    break;
		    default:
			    argerrs++;
			    break;
	    }
    }
    if (argerrs)
	    cmd_usage(pc->curcmd, SYNOPSIS);
}

Memblock::Memblock(){
    field_init(memblock,bottom_up);
    field_init(memblock,current_limit);
    field_init(memblock,memory);
    field_init(memblock,reserved);
    field_init(memblock_type,cnt);
    field_init(memblock_type,max);
    field_init(memblock_type,total_size);
    field_init(memblock_type,regions);
    field_init(memblock_type,name);
    field_init(memblock_region,base);
    field_init(memblock_region,size);
    field_init(memblock_region,flags);
    struct_init(memblock);
    struct_init(memblock_type);
    struct_init(memblock_region);
    cmd_name = "memblock";
    help_str_list={
	    "memblock",				/* command name */
	    "dump memblock memory information",	/* short description */
	    "-a \n"
		    "\n",
	    "EXAMPLES",
	    "  Display memblock memory info:",
	    "    %s> memblock -a",
	    "	memblock_type:0xffffffde30f33048 [memory] total size:1.98Gb",
	    "	  [0]  memblock_region:0xffffffde310dc8a8 range:[0x40000000~0x45700000] size:87.00Mb    flags:MEMBLOCK_NONE",
	    "	  [1]  memblock_region:0xffffffde310dc8c0 range:[0x45700000~0x45f1b000] size:8.11Mb     flags:MEMBLOCK_NOMAP",
	    "	  [2]  memblock_region:0xffffffde310dc8d8 range:[0x45f1b000~0x45fff000] size:912.00Kb   flags:MEMBLOCK_NONE",
	    "",
	    "	memblock_type:0xffffffde30f33070 [reserved] total size:352.26Mb",
	    "	  [0]  memblock_region:0xffffffde310dd4a8 range:[0x40010000~0x42ccd000] size:44.74Mb    flags:MEMBLOCK_NONE",
	    "	  [1]  memblock_region:0xffffffde310dd4c0 range:[0x44a75000~0x44abfb5c] size:298.84Kb   flags:MEMBLOCK_NONE",
	    "	  [2]  memblock_region:0xffffffde310dd4d8 range:[0x47fffe80~0x48000000] size:384b       flags:MEMBLOCK_NONE",
	    "\n",
    };
    initialize();
    parser_memblock();
}

static std::vector<std::string> flags_str = {
	"MEMBLOCK_NONE",
	"MEMBLOCK_HOTPLUG",
	"MEMBLOCK_MIRROR",
	"",
	"MEMBLOCK_NOMAP",
};

void Memblock::parser_memblock(){
    if (!csymbol_exists("memblock")){
        LOGE("memblock doesn't exist in this kernel!\n");
        return;
    }
    ulong memblock_addr = csymbol_value("memblock");
    if (!is_kvaddr(memblock_addr)) return;
    void *buf = read_struct(memblock_addr,"memblock");
    if(buf == nullptr) return;
    block = std::make_shared<memblock>();
    block->addr = memblock_addr;
    block->bottom_up = BOOL(buf + field_offset(memblock,bottom_up));
    block->current_limit = ULONG(buf + field_offset(memblock,current_limit));
    FREEBUF(buf);
    parser_memblock_type(memblock_addr + field_offset(memblock,memory),&block->memory);
    parser_memblock_type(memblock_addr + field_offset(memblock,reserved),&block->reserved);
}

void Memblock::parser_memblock_type(ulong addr,memblock_type* type){
    void *buf = read_struct(addr,"memblock_type");
    if(buf == nullptr) return;
    type->addr = addr;
    type->cnt = ULONG(buf + field_offset(memblock_type,cnt));
    type->max = ULONG(buf + field_offset(memblock_type,max));
    if(get_config_val("CONFIG_PHYS_ADDR_T_64BIT") == "y"){
        type->total_size = (ulong)ULONGLONG(buf + field_offset(memblock_type,total_size));
    }else{
        type->total_size = ULONG(buf + field_offset(memblock_type,total_size));
    }
    type->name = read_cstring(ULONG(buf + field_offset(memblock_type,name)),64, "memblock_type_name");
    ulong regions = ULONG(buf + field_offset(memblock_type,regions));
    FREEBUF(buf);
    type->regions = parser_memblock_region(regions,type->cnt);
}

std::vector<std::shared_ptr<memblock_region>> Memblock::parser_memblock_region(ulong addr,int cnt){
    std::vector<std::shared_ptr<memblock_region>> res;
    for (int i = 0; i < cnt; ++i) {
        ulong reg_addr = addr + i * struct_size(memblock_region);
        void *buf = read_struct(reg_addr,"memblock_region");
        if(buf == nullptr) return res;
        std::shared_ptr<memblock_region> region = std::make_shared<memblock_region>();
        region->addr = reg_addr;
        if(get_config_val("CONFIG_PHYS_ADDR_T_64BIT") == "y"){
            region->base = (ulong)ULONGLONG(buf + field_offset(memblock_region,base));
            region->size = (ulong)ULONGLONG(buf + field_offset(memblock_region,size));
        }else{
            region->base = ULONG(buf + field_offset(memblock_region,base));
            region->size = ULONG(buf + field_offset(memblock_region,size));
        }
        region->flags = (enum memblock_flags)INT(buf + field_offset(memblock_region,flags));
        FREEBUF(buf);
        res.push_back(region);
    }
    return res;
}

void Memblock::print_memblock(){
    char buf[BUFSIZE];
    if (block.get() == nullptr){
        fprintf(fp, "Parser memblock fail !");
        return;
    }
    convert_size(block->memory.total_size,buf);
    fprintf(fp, "memblock_type:0x%lx [%s] total size:%s\n",block->memory.addr,block->memory.name.c_str(),buf);
    print_memblock_type(&block->memory);
    fprintf(fp, "\n");
    convert_size(block->reserved.total_size,buf);
    fprintf(fp, "memblock_type:0x%lx [%s] total size:%s\n",block->reserved.addr,block->reserved.name.c_str(),buf);
    print_memblock_type(&block->reserved);
}

void Memblock::print_memblock_type(memblock_type* type){
    char buf[BUFSIZE];
    for (int i = 0; i < type->cnt; ++i) {
        sprintf(buf, "  [%d]",i);
        fprintf(fp, "%s ",mkstring(buf, 6, LJUST, buf));

        fprintf(fp, "memblock_region:0x%lx ",type->regions[i]->addr);
        fprintf(fp, "range:[0x%llx~0x%llx] ",(ulonglong)type->regions[i]->base,(ulonglong)(type->regions[i]->base + type->regions[i]->size));
        convert_size(type->regions[i]->size,buf);
        fprintf(fp, "size:%s ",mkstring(buf, 10, LJUST,buf));
        fprintf(fp, "flags:%s\n",flags_str[type->regions[i]->flags].c_str());
    }
}
#pragma GCC diagnostic pop
