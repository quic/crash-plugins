// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "memory.h"

static void memory_init(void);
static void memory_fini(void);
static void cmd_memory(void);

char *help_memory[] = {
	"mm",							/* command name */
	"dump memory info",		/* short description */
	"-v \n"
    "  mm -c\n"
    "  mm -r\n"
    "  mm -m\n"
    "  mm -b\n"
    "  mm -d\n"
    "  mm -s\n",				    /* argument synopsis, or " " if none */			       
	"  This command dumps the memory info.",
    "\n",
    "EXAMPLES",
	"  Display vmalloc memory info:",
	"    %s> mm -v",
	"       vmap_area:0xf1e85840 range:0xbf000000 ~ 0xbf005000 size:20K",
	"         vm_struct:0xf1a01ac0 size:20K flags:vmalloc nr_pages:4 addr:0xbf000000 phys_addr:0x0 load_module+3880",
    "           Page:0xf80855b8 PA:0xa057e000",
    "           Page:0xf80855dc PA:0xa057f000",
    "\n",
    "  Display cma memory info:",
	"    %s> mm -c",
	"       cma_area_count:2",
	"       ======================================================================",
    "       adsp_region               cma:0xc2533e9c PFN:0xbc000~0xbc800 size:8192K    used:8040K    order:0",
    "       linux,cma                 cma:0xc2533e50 PFN:0xbc800~0xbe800 size:32768K   used:48808K   order:0",
    "       ======================================================================",
    "       total cma size:100.00M",
    "\n",
	"  Display reserved memory info", 
	"    %s> mm -r",
	"       ======================================================================",
    "       modem_region@4ab00000          reserved_mem:0xc25a6fc8 range:0x4ab00000~0x50900000 size:96256K",
    "       removed_region@60100000        reserved_mem:0xc25a70c4 range:0x60100000~0x61f00000 size:30720K",
    "       linux,cma                      reserved_mem:0xc25a6e94 range:0xbc800000~0xbe800000 size:32768K",
    "       ======================================================================",
    "       total reserved memory size:282.20M",
    "\n",
	"  Display memblock memory info:", 
	"    %s> mm -m",
    "       memblock_type:0xc203a960 [memory] size:1863.80M",
    "          memblock_region:0xc2273b68 range:0x40000000~0x45700000 size:87.00M    flags:MEMBLOCK_NONE" ,
    "          memblock_region:0xc2273b74 range:0x45f1b000~0x45fff000 size:912.00K   flags:MEMBLOCK_NONE" ,
    "       memblock_type:0xc203a974 [reserved] size:160.49M",
    "          memblock_region:0xc2274174 range:0x40100000~0x42883fd4 size:39.52M    flags:MEMBLOCK_NONE" ,
    "          memblock_region:0xc2274180 range:0x453b2000~0x453fdfba size:303.93K   flags:MEMBLOCK_NONE" ,
    "\n",
	"  Display dma_buf memory info:", 
	"    %s> mm -d",
    "       dma_buf:0xde20950c [ion_dma_buf] priv:0xef55ce80 f_count:7 size:452K",
    "          dma_buf_attachment:0xeb976840 device:0xf65fd410[soc:qcom,smmu_sde_unsec_cb] driver:0xc2168640[msmdrm_smmu] priv:0xeb976200",
    "          dma_buf_attachment:0xe919bfc0 device:0xf4212400[kgsl-3d0] driver:0x0[unknow] priv:0xd8d7d800",
    "          dma_buf_attachment:0xe9c3c1c0 device:0xf4212400[kgsl-3d0] driver:0x0[unknow] priv:0xe9c3c840",
    "\n",
	"  Display buddy info:",
	"    %s> mm -b",
    "       Free pages count per migrate type at order  [0-10]:",
    "       Node(0)" ,
    "       -----------------------------------------------------------------------------------------------------",
    "                                                   zone DMA32                                               ",
    "       -----------------------------------------------------------------------------------------------------",
    "                 Order     4K     8K    16K    32K    64K   128K   256K   512K  1024K  2048K  4096K    Total",
    "              Movable   5496   3435   1998    764    145     33      5      0      0      0      0   120664K",
    "          Reclaimable    135     39     94     56      0      0      0      0      0      0      0     4148K",
    "\n",
    "  Display detail memory info:",
	"    %s> mm -s",
    "       Memory breakdown:",
    "       RAM:                         41.98GB",
    "       Carveout:                    30.69GB",
    "          No-Map:                   481.45MB",
    "           Other:                   30.22GB",
    "       MemTotal:                    10.98GB",
    "         MemFree:                   5.30GB",
    "         Buffers:                   9.59MB",
    "\n",
    NULL
};

static struct command_table_entry command_table[] = {
    { "mm", cmd_memory, help_memory, 0 },
    { NULL }
};

struct memory_offset_table {
    DEFINE_MEMBER(vmap_area,list)
    DEFINE_MEMBER(vm_struct,next)
    DEFINE_MEMBER(vm_struct,addr)
    DEFINE_MEMBER(vm_struct,size)
    DEFINE_MEMBER(vm_struct,flags)
    DEFINE_MEMBER(vm_struct,pages)
    DEFINE_MEMBER(vm_struct,nr_pages)
    DEFINE_MEMBER(vm_struct,phys_addr)
    DEFINE_MEMBER(vm_struct,caller)
    DEFINE_MEMBER(cma,base_pfn)
    DEFINE_MEMBER(cma,count)
    DEFINE_MEMBER(cma,bitmap)
    DEFINE_MEMBER(cma,order_per_bit)
    DEFINE_MEMBER(cma,name)
    DEFINE_MEMBER(reserved_mem,name)
    DEFINE_MEMBER(reserved_mem,base)
    DEFINE_MEMBER(reserved_mem,size)

    DEFINE_MEMBER(memblock,memory)
    DEFINE_MEMBER(memblock,reserved)
    DEFINE_MEMBER(memblock_type,cnt)
    DEFINE_MEMBER(memblock_type,max)
    DEFINE_MEMBER(memblock_type,total_size)
    DEFINE_MEMBER(memblock_type,regions)
    DEFINE_MEMBER(memblock_type,name)
    DEFINE_MEMBER(memblock_region,base)
    DEFINE_MEMBER(memblock_region,size)
    DEFINE_MEMBER(memblock_region,flags)

    DEFINE_MEMBER(dma_buf,list_node)
    DEFINE_MEMBER(dma_buf,size)
    DEFINE_MEMBER(dma_buf,attachments)
    DEFINE_MEMBER(dma_buf,exp_name)
    DEFINE_MEMBER(dma_buf,name)
    DEFINE_MEMBER(dma_buf,priv)
    DEFINE_MEMBER(dma_buf,file)
    DEFINE_MEMBER(dma_buf_attachment,node)
    DEFINE_MEMBER(dma_buf_attachment,dev)
    DEFINE_MEMBER(dma_buf_attachment,priv)
    DEFINE_MEMBER(file,f_count)

    DEFINE_MEMBER(device,driver)

    DEFINE_MEMBER(device_node,name)
    DEFINE_MEMBER(device_node,phandle)
    DEFINE_MEMBER(device_node,full_name)
    DEFINE_MEMBER(device_node,fwnode)
    DEFINE_MEMBER(device_node,properties)
    DEFINE_MEMBER(device_node,parent)
    DEFINE_MEMBER(device_node,child)
    DEFINE_MEMBER(device_node,sibling)

    DEFINE_MEMBER(property,name)
    DEFINE_MEMBER(property,length)
    DEFINE_MEMBER(property,value)
    DEFINE_MEMBER(property,next)

    DEFINE_MEMBER(zone,zone_start_pfn)
    DEFINE_MEMBER(zone,managed_pages)
    DEFINE_MEMBER(zone,spanned_pages)
    DEFINE_MEMBER(zone,present_pages)
    DEFINE_MEMBER(zone,present_early_pages)
    DEFINE_MEMBER(zone,cma_pages)

    DEFINE_MEMBER(block_device,bd_inode)
    DEFINE_MEMBER(block_device,bd_list)
    DEFINE_MEMBER(inode,i_mapping)
    DEFINE_MEMBER(inode,i_sb_list)
    DEFINE_MEMBER(address_space,nrpages)
    DEFINE_MEMBER(super_block,s_inodes)
} memory_offset_table;

static void offset_table_init(void) {
	BZERO(&memory_offset_table, sizeof(memory_offset_table));
    field_offset_init(vmap_area,list);
    field_offset_init(vm_struct,next);
    field_offset_init(vm_struct,addr);
    field_offset_init(vm_struct,size);
    field_offset_init(vm_struct,flags);
    field_offset_init(vm_struct,pages);
    field_offset_init(vm_struct,nr_pages);
    field_offset_init(vm_struct,phys_addr);
    field_offset_init(vm_struct,caller);
    field_offset_init(cma,base_pfn);
    field_offset_init(cma,count);
    field_offset_init(cma,bitmap);
    field_offset_init(cma,order_per_bit);
    field_offset_init(cma,name);
    field_offset_init(reserved_mem,name);
    field_offset_init(reserved_mem,base);
    field_offset_init(reserved_mem,size);

    field_offset_init(memblock,memory);
    field_offset_init(memblock,reserved);
    field_offset_init(memblock_type,cnt);
    field_offset_init(memblock_type,max);
    field_offset_init(memblock_type,total_size);
    field_offset_init(memblock_type,regions);
    field_offset_init(memblock_type,name);
    field_offset_init(memblock_region,base);
    field_offset_init(memblock_region,size);
    field_offset_init(memblock_region,flags);

    field_offset_init(dma_buf,list_node);
    field_offset_init(dma_buf,size);
    field_offset_init(dma_buf,attachments);
    field_offset_init(dma_buf,exp_name);
    field_offset_init(dma_buf,name);
    field_offset_init(dma_buf,priv);
    field_offset_init(dma_buf,file);
    field_offset_init(dma_buf_attachment,node);
    field_offset_init(dma_buf_attachment,dev);
    field_offset_init(dma_buf_attachment,priv);
    field_offset_init(file,f_count);

    field_offset_init(device,driver);

    field_offset_init(device_node,name);
    field_offset_init(device_node,phandle);
    field_offset_init(device_node,full_name);
    field_offset_init(device_node,fwnode);
    field_offset_init(device_node,properties);
    field_offset_init(device_node,parent);
    field_offset_init(device_node,child);
    field_offset_init(device_node,sibling);

    field_offset_init(property,name);
    field_offset_init(property,length);
    field_offset_init(property,value);
    field_offset_init(property,next);

    field_offset_init(zone,zone_start_pfn);
    field_offset_init(zone,managed_pages);
    field_offset_init(zone,spanned_pages);
    field_offset_init(zone,present_pages);
    field_offset_init(zone,present_early_pages);
    field_offset_init(zone,cma_pages);

    field_offset_init(block_device,bd_inode);
    field_offset_init(block_device,bd_list);
    field_offset_init(inode,i_mapping);
    field_offset_init(inode,i_sb_list);
    field_offset_init(address_space,nrpages);
    field_offset_init(super_block,s_inodes);
}

/**define all the struct which need calc struct size */
static struct memory_size_table {
    long vmap_area;
    long vm_struct;
    long cma;
    long reserved_mem;
    long memblock_type;
    long memblock_region;
    long dma_buf;
    long dma_buf_attachment;
    long file;
    long device;
    long device_driver;
    long device_node;
    long property;
    long zone;
    long page;
    long address_space;
    long hlist_bl_head;
    long hlist_head;
    DEFINE_MEMBER(vm_struct,size)
} memory_size_table;

static void size_table_init(void) {
	BZERO(&memory_size_table, sizeof(memory_size_table));
    struct_size_init(vmap_area);
    struct_size_init(vm_struct);
    struct_size_init(cma);
    struct_size_init(reserved_mem);
    struct_size_init(memblock_type);
    struct_size_init(memblock_region);
    struct_size_init(dma_buf);
    struct_size_init(dma_buf_attachment);
    struct_size_init(file);
    struct_size_init(device);
    struct_size_init(device_driver);
    struct_size_init(device_node);
    struct_size_init(property);
    struct_size_init(zone);
    struct_size_init(page);
    struct_size_init(address_space);
    struct_size_init(hlist_bl_head);
    struct_size_init(hlist_head);
    field_size_init(vm_struct, size); 
}

void __attribute__((constructor)) memory_init(void) {
    register_extension(command_table);
    offset_table_init();
    size_table_init();
}

void __attribute__((destructor)) memory_fini(void) {
    // fprintf(fp, "memory_fini\n");
}

void cmd_memory(void)
{
    int c;
    // int flags;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "vcrbdms")) != EOF) {
		switch(c) {
            case 'v': //print vmalloc memory 
                parser_vmap_area_list();
                break;
            case 'c': //print cma info
                parser_cma_areas();
                break;
            case 'r': //print reserved memory
                parser_reserved_mem();
                break;
            case 'm': //print memory block
                parser_mem_block();
                break;
            case 'd': //print dma buffer
                parser_dma_buf();
                break;
            case 'b': //print buddy info
                parser_buddy_info();
                break;
            case 's': //print memory info
                parser_memory_info();
                break;
            default:
                argerrs++;
                break;
		}
	}
    if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);
}

ulong mm_get_ddr_size(){
    if (!symbol_exists("of_root")){
        error(FATAL, "of_root doesn't exist in this kernel!\n");
        return 0;
    }
    ulong node = mm_find_node_by_path("/memory");
    if (node == 0)
        return 0;
    char size_buf[BUFSIZE];
    void *node_buf = mm_read_struct(node,struct_size(device_node),"device_node");
    if(node_buf == NULL) return 0;
    ulong properties = ULONG(node_buf + field_offset(device_node,properties));
    FREEBUF(node_buf);
    if (properties == 0)
        return 0;
    ulong val_addr = 0;
    bool has_mem_node = mm_has_prop_name(properties,"device_type");
    // read property of device_type
    int len = mm_get_prop_value(properties,"device_type", &val_addr);
    void *prop_val = mm_read_struct(val_addr,len,"property_value");
    if (!has_mem_node || strcmp(prop_val, "memory")){
        return 0;
    }
    // read property of reg
    //       <|  start     | |   size     |
    // reg = <0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000>
    len = mm_get_prop_value(properties,"reg", &val_addr);
    prop_val = mm_read_struct(val_addr,len,"property_value");
    int count = len / 4;
    long long unsigned regs[count];
    for (int i = 0; i < count; ++i) {
        regs[i] = mm_bigToLittleEndian(UINT(prop_val + i * sizeof(int)));
    }
    int group_cnt = count / 4;
    ulong total_size = 0;
    fprintf(fp, "=====================================================\n");
    for (int i = 0; i < group_cnt; ++i) {
        long long unsigned addr = (regs[i * 4 + 0] << 32) | regs[i * 4 + 1];
        long long unsigned size = (regs[i * 4 + 2] << 32) | regs[i * 4 + 3];
        sprintf(size_buf, "0x%llx~0x%llx",addr,(addr + size));
        fprintf(fp, "  %s size:0x%llx\n",mkstring(size_buf, 30, LJUST,size_buf),size);
        total_size += size;
    }
    fprintf(fp, "=====================================================\n");
    convert_size(total_size,size_buf);
    fprintf(fp, "Total size:%s", size_buf);
    return total_size;
}

unsigned int mm_bigToLittleEndian(unsigned int num) {
    return ((num >> 24) & 0xFF) | ((num >> 8) & 0xFF00) | ((num << 8) & 0xFF0000) | ((num << 24) & 0xFF000000);
}

bool mm_has_prop_name(ulong addr,char *name){
    while (addr)
    {
        void *prop_buf = mm_read_struct(addr,struct_size(property),"property");
        if(prop_buf == NULL) return false;
        ulong name_addr = ULONG(prop_buf + field_offset(property,name));
        // read name
        char prop_name[64];
        mm_read_cstring(name_addr,prop_name,64, "property_name");
        if (!strcmp(prop_name, name)) {
            FREEBUF(prop_buf);
            return true;
        }
        addr = ULONG(prop_buf + field_offset(property,next));
        FREEBUF(prop_buf);
    }
    return false;
}

int mm_get_prop_value(ulong addr,char *name, ulong* data){
    int length = 0;
    while (addr)
    {
        void *prop_buf = mm_read_struct(addr,struct_size(property),"property");
        if(prop_buf == NULL) return 0;
        ulong name_addr = ULONG(prop_buf + field_offset(property,name));
        // read name
        char prop_name[64];
        mm_read_cstring(name_addr,prop_name,64, "property_name");
        // fprintf(fp, "property_name:%s\n",prop_name);
        if (strcmp(prop_name, name)) {
            addr = ULONG(prop_buf + field_offset(property,next));
            FREEBUF(prop_buf);
            continue;
        }
        length = UINT(prop_buf + field_offset(property,length));
        *data = ULONG(prop_buf + field_offset(property,value));
        addr = ULONG(prop_buf + field_offset(property,next));
        FREEBUF(prop_buf);
    }
    return length;
}

ulong mm_find_node_by_fullname(char *full_name){
    ulong node = 0;
    ulong of_root_addr = symbol_value("of_root");
    if (!of_root_addr) return 0;
    ulong of_root = mm_read_pointer(of_root_addr,"of_root");
    for (node = mm_find_all_nodes(of_root,of_root); node; node = mm_find_all_nodes(node,of_root)){
        if (mm_node_fullname_eq(node, full_name)){
            return node;
        }
    } 
    return 0;
}

ulong mm_find_node_by_name(char *name){
    ulong node = 0;
    ulong of_root_addr = symbol_value("of_root");
    if (!of_root_addr) return 0;
    ulong of_root = mm_read_pointer(of_root_addr,"of_root");
    for (node = mm_find_all_nodes(of_root,of_root); node; node = mm_find_all_nodes(node,of_root)){
        if (mm_node_name_eq(node, name)){
            return node;
        }
    } 
    return 0;
}

ulong mm_find_node_by_path(char *path){
	ulong np = 0;
    ulong of_root_addr = symbol_value("of_root");
    if (!of_root_addr) return 0;
    ulong of_root = mm_read_pointer(of_root_addr,"of_root");
	if (strcmp(path, "/") == 0)
		return of_root;
	if (!np)
		np = of_root;
	np = mm_find_node_by_full_path(np, path);
	return np;
}

ulong mm_find_node_by_full_path(ulong node,char *path){
	const char *separator = strchr(path, ':');
	while (node && *path == '/') {
		path++; /* Increment past '/' delimiter */
		node = mm_of_find_node_by_path(node, path);
		path = mm_strchrnul(path, '/');
		if (separator && separator < path)
			break;
	}
	return node;
}

ulong mm_of_find_node_by_path(ulong parent,const char *path){
	ulong child;
	int len;
	len = strcspn(path, "/:");
	if (!len)
		return 0;
	for (child = mm_of_get_next_child(parent, 0); child != 0; \
	     child = mm_of_get_next_child(parent, child)) {
        void *node_buf = mm_read_struct(child,struct_size(device_node),"device_node");
        if(node_buf == NULL) return false;
        // ulong node_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
        ulong node_name_addr = ULONG(node_buf + field_offset(device_node,name));
        char node_name[64];
        mm_read_cstring(node_name_addr,node_name,64, "device_node_full_name");
        FREEBUF(node_buf);
		char *name = mm_kbasename(node_name);
		if (strncmp(path, name, len) == 0 && (strlen(name) == len))
			return child;
	}
	return 0;
}

ulong mm_of_get_next_child(ulong node,ulong prev){
	ulong next;
	if (!node)
		return 0;
    if (prev > 0){
        void *node_buf = mm_read_struct(prev,struct_size(device_node),"device_node");
        if(node_buf == NULL) return 0;
        ulong sibling = ULONG(node_buf + field_offset(device_node,sibling));
        FREEBUF(node_buf);
        next = sibling;
    }else{
        void *node_buf = mm_read_struct(node,struct_size(device_node),"device_node");
        if(node_buf == NULL) return 0;
        ulong child = ULONG(node_buf + field_offset(device_node,child));
        FREEBUF(node_buf);
        next = child;
    }
	return next;
}

ulong mm_find_all_nodes(ulong prev,ulong root){
	ulong parent,child,sibling;
    ulong np = 0;
    void *node_buf = mm_read_struct(prev,struct_size(device_node),"device_node");
    if(node_buf == NULL) return np;
    parent = ULONG(node_buf + field_offset(device_node,parent));
    child = ULONG(node_buf + field_offset(device_node,child));
    sibling = ULONG(node_buf + field_offset(device_node,sibling));
    FREEBUF(node_buf);
	if (!prev) {
		np = root;
	} else if (child) {
		np = child;
	} else {
		/* Walk back up looking for a sibling, or the end of the structure */
		np = prev;
        void *node_buf = mm_read_struct(np,struct_size(device_node),"device_node");
        if(node_buf == NULL) return np;
        parent = ULONG(node_buf + field_offset(device_node,parent));
        sibling = ULONG(node_buf + field_offset(device_node,sibling));
        FREEBUF(node_buf);
		while (parent && !sibling){
            np = parent;
            void *node_buf = mm_read_struct(np,struct_size(device_node),"device_node");
            if(node_buf == NULL) return np;
            parent = ULONG(node_buf + field_offset(device_node,parent));
            sibling = ULONG(node_buf + field_offset(device_node,sibling));
            FREEBUF(node_buf);
        }
		np = sibling; /* Might be null at the end of the tree */
	}
	return np;
}

bool mm_node_fullname_eq(ulong np, char *name){
	char *node_name;
	size_t len;
	if (!np)
		return false;
    void *node_buf = mm_read_struct(np,struct_size(device_node),"device_node");
    if(node_buf == NULL) return false;
    ulong full_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
    // read full name
    char full_name[64];
    mm_read_cstring(full_name_addr,full_name,64, "device_node_full_name");
    FREEBUF(node_buf);
	node_name = mm_kbasename(full_name);
	len = mm_strchrnul(node_name, '@') - node_name;
	return (strlen(name) == len) && (strncmp(node_name, name, len) == 0);
}

bool mm_node_name_eq(ulong np, char *name){
	if (!np)
		return false;
    void *node_buf = mm_read_struct(np,struct_size(device_node),"device_node");
    if(node_buf == NULL) return false;
    ulong name_addr = ULONG(node_buf + field_offset(device_node,name));
    // read name
    char nd_name[64];
    mm_read_cstring(name_addr,nd_name,64, "device_node_name");
    if (!strcmp(nd_name, name)) {
        return true;
    }
    ulong full_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
    // read full name
    char full_name[64];
    mm_read_cstring(full_name_addr,full_name,64, "device_node_full_name");
    if (!strcmp(full_name, name)) {
        return true;
    }
    FREEBUF(node_buf);
	return false;
}

char *mm_strchrnul(char *s, int c){
	while (*s && *s != (char)c)
		s++;
	return (char *)s;
}

char *mm_kbasename(char *path){
	char *tail = strrchr(path, '/');
	return tail ? tail + 1 : path;
}

ulong get_cma_size(){
    ulong total_size = 0;
    if (!symbol_exists("cma_areas")){
        return 0;
    }
    ulong cma_areas_addr = symbol_value("cma_areas");
    ulong cma_area_count = mm_read_pointer(symbol_value("cma_area_count"),"cma_area_count");
    for (int i = 0; i < cma_area_count; ++i) {
        ulong cma_addr = cma_areas_addr + i * struct_size(cma);
        void *cma_buf = mm_read_struct(cma_addr,struct_size(cma),"cma");
        if(cma_buf == NULL) return 0;
        ulong count = ULONG(cma_buf + field_offset(cma,count));
        ulong bitmap = ULONG(cma_buf + field_offset(cma,bitmap));
        int order_per_bit = UINT(cma_buf + field_offset(cma,order_per_bit));
        ulong allocated_size = get_cma_used_size(bitmap,count,order_per_bit);
        total_size += allocated_size;
        FREEBUF(cma_buf);
    }
    return total_size;
}

ulong get_vmalloc_size(){
    if (!symbol_exists("vmap_area_list")){
        return 0;
    }
    ulong vmap_area_list = symbol_value("vmap_area_list");
    // read all vmap_area
    ulong* vmap_area_data = NULL;
    int total_size = 0;
    int offset = field_offset(vmap_area,list);
    int cnt = mm_for_each_list_entry(vmap_area_list,offset,&vmap_area_data);
    for (int i = 0; i < cnt; ++i) {
        ulong vmap_area_addr = vmap_area_data[i];
        if (vmap_area_addr <= 0) continue;
        struct vmap_area vmap_area;
        if (!readmem(vmap_area_addr, KVADDR, &vmap_area, sizeof(struct vmap_area), "vmap_area", FAULT_ON_ERROR)){
            continue;
        }
        ulong varea_size = vmap_area.va_end - vmap_area.va_start;
        if (vmap_area.va_start == 0 || vmap_area.va_start == 0 || varea_size == 0) continue;
        ulong vm_addr = (ulong)vmap_area.vm;
        while (vm_addr > 0){
            int buf_size = struct_size(vm_struct);
            void* vm_struct_buf = (void *)GETBUF(buf_size);
            if (!readmem(vm_addr, KVADDR, vm_struct_buf, buf_size, "vm_struct", RETURN_ON_ERROR|QUIET)) {
                FREEBUF(vm_struct_buf);
                break;
            }
            ulong next = ULONG(vm_struct_buf + field_offset(vm_struct,next));
            int nr_pages = UINT(vm_struct_buf + field_offset(vm_struct,nr_pages));
            total_size += nr_pages;
            FREEBUF(vm_struct_buf);
            vm_addr = next;
        }
    }
    FREEBUF(vmap_area_data);
    return total_size*PAGESIZE();
}

ulong get_dma_size(){
    if (!symbol_exists("db_list")){
        return 0;
    }
    ulong db_list_addr = symbol_value("db_list");
    ulong* dma_buf_data = NULL;
    int total_size = 0;
    int offset = field_offset(dma_buf,list_node);
    int cnt = mm_for_each_list_entry(db_list_addr,offset,&dma_buf_data);
    for (int i = 0; i < cnt; ++i) {
        ulong dma_buf_addr = dma_buf_data[i];
        if (dma_buf_addr <= 0) continue;
        void *dma_buf = mm_read_struct(dma_buf_addr,struct_size(dma_buf),"dma_buf");
        if(dma_buf == NULL) continue;
        int size = INT(dma_buf + field_offset(dma_buf,size));
        total_size += size;
        FREEBUF(dma_buf);
    }
    if(dma_buf_data != NULL)FREEBUF(dma_buf_data);
    return total_size;
}

void parser_memory_info(){
    struct node_table *nt;
    ulong node_zones;
    ulong total_hole_pages = 0;
    ulong total_reserve_pages = 0;
    ulong total_spanned_pages = 0;
    ulong temp;
    char zone_name[BUFSIZE];
    char size_buf[BUFSIZE];
    fprintf(fp, "Memory config:\n");
    ulong mem_total_size = mm_get_ddr_size();
    fprintf(fp, "\n\n\n");
    fprintf(fp, "Physic memory:\n");
    fprintf(fp, "==============================================================================================================\n");
    for (int n = 0; n < vt->numnodes; n++) {
		nt = &vt->node_table[n];
        ulong spanned_size = nt->size*PAGESIZE();
        ulong present_size = nt->present*PAGESIZE();
        ulong hole_pages = nt->size - nt->present;
        ulong hole_size = hole_pages*PAGESIZE();
        total_hole_pages += hole_pages;
        total_spanned_pages += nt->size;
        fprintf(fp, "Node(%lx) ",nt->pgdat);
        convert_size(spanned_size,size_buf);
        fprintf(fp, "spanned:%ld(%s) ",nt->size, size_buf);
        convert_size(present_size,size_buf);
        fprintf(fp, "present:%ld(%s) ",nt->present, size_buf);
        convert_size(hole_size,size_buf);
        fprintf(fp, "hole:%ld(%s) ",hole_pages, size_buf);
        fprintf(fp, "start_pfn:%ld ",nt->start_mapnr);
        fprintf(fp, "start_paddr:%llx \n",nt->start_paddr);
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);
		for (int z = 0; z < vt->nr_zones; z++) {
			ulong zone_addr = (node_zones + (z * SIZE(zone)));
			readmem(zone_addr + OFFSET(zone_name), KVADDR, &temp,sizeof(void *), "node_zones name",FAULT_ON_ERROR);
			read_string(temp, zone_name, BUFSIZE-1);
            void *zone_buf = mm_read_struct(zone_addr,struct_size(zone),"zone");
            if(zone_buf == NULL) continue;
            ulong zone_start_pfn = ULONG(zone_buf + field_offset(zone,zone_start_pfn));
            ulong managed_pages = ULONG(zone_buf + field_offset(zone,managed_pages));
            ulong spanned_pages = ULONG(zone_buf + field_offset(zone,spanned_pages));
            ulong present_pages = ULONG(zone_buf + field_offset(zone,present_pages));
            ulong absent_pages = spanned_pages - present_pages;
            ulong reserved_pages = present_pages - managed_pages;
            total_reserve_pages += reserved_pages;
            fprintf(fp, "   %s zone(%lx) ",mkstring(zone_name, 9, LJUST,zone_name),zone_addr);
            convert_size(spanned_pages*PAGESIZE(),size_buf);
            fprintf(fp, "spanned:%ld(%s) ",spanned_pages, size_buf);
            convert_size(present_pages*PAGESIZE(),size_buf);
            fprintf(fp, "present:%ld(%s) ",present_pages, size_buf);
            convert_size(absent_pages*PAGESIZE(),size_buf);
            fprintf(fp, "hole:%ld(%s) ",absent_pages, size_buf);
            convert_size(managed_pages*PAGESIZE(),size_buf);
            fprintf(fp, "managed:%ld(%s) ",managed_pages, size_buf);
            convert_size(reserved_pages*PAGESIZE(),size_buf);
            fprintf(fp, "reserved:%ld(%s) ",reserved_pages, size_buf);
            if (valid_field(zone,cma_pages)){
                ulong cma_pages = ULONG(zone_buf + field_offset(zone,cma_pages));
                convert_size(cma_pages*PAGESIZE(),size_buf);
                fprintf(fp, "cma_pages:%ld(%s) ",cma_pages, size_buf);
            }
            fprintf(fp, "start_pfn:%ld \n",zone_start_pfn);
            FREEBUF(zone_buf);
        }
    }
    fprintf(fp, "==============================================================================================================\n\n\n");
    fprintf(fp, "Memory breakdown:\n");
    fprintf(fp, "====================================================\n");
    ulong rem_total_size = 0;
    ulong nomap_size = 0;
    ulong reusable_size = 0;
    char prefix_buf[BUFSIZE];
    get_reserved_mem(&rem_total_size,&nomap_size,&reusable_size);
    
    struct sysinfo meminfo;
    ulong pages[NR_LRU_LISTS];
    long slab_rec_index = 0;
    long slab_unrec_index = 0;
    long free_index = 0;
    long shmem_index = 0;
    long swapcache_index = 0;
    long filepages_index = 0;
    long kernelstack_index = 0;
    long pagetable_index = 0;
    long lru_base_index = 0;
    if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
        enumerator_value("NR_SLAB_RECLAIMABLE_B", &slab_rec_index);
        enumerator_value("NR_SLAB_UNRECLAIMABLE_B", &slab_unrec_index);
    }else{
        enumerator_value("NR_SLAB_RECLAIMABLE", &slab_rec_index);
        enumerator_value("NR_SLAB_UNRECLAIMABLE", &slab_unrec_index);
    }
    enumerator_value("NR_FREE_PAGES", &free_index);
    enumerator_value("NR_SHMEM", &shmem_index);
    enumerator_value("NR_SWAPCACHE", &swapcache_index);
    enumerator_value("NR_FILE_PAGES", &filepages_index);
    enumerator_value("NR_KERNEL_STACK_KB", &kernelstack_index);
    enumerator_value("NR_PAGETABLE", &pagetable_index);
    enumerator_value("NR_LRU_BASE", &lru_base_index);
    if (symbol_exists("vm_node_stat") && symbol_exists("vm_zone_stat")){
        long zone_cnt = 0;
        enumerator_value("NR_VM_ZONE_STAT_ITEMS", &zone_cnt);
        ulong *vm_zone_stat_buf = (ulong *)GETBUF(sizeof(ulong) * zone_cnt);
        readmem(symbol_value("vm_zone_stat"), KVADDR, vm_zone_stat_buf,sizeof(ulong) * zone_cnt,"vm_zone_stat", FAULT_ON_ERROR);

        long node_cnt = 0;
        enumerator_value("NR_VM_NODE_STAT_ITEMS", &node_cnt);
        ulong *vm_node_stat_buf = (ulong *)GETBUF(sizeof(ulong) * node_cnt);
        readmem(symbol_value("vm_node_stat"), KVADDR, vm_node_stat_buf,sizeof(ulong) * node_cnt,"vm_node_stat", FAULT_ON_ERROR);

        meminfo.sharedram = vm_node_stat_buf[shmem_index];
        meminfo.swapcache = vm_node_stat_buf[swapcache_index];
        meminfo.filepages = vm_node_stat_buf[filepages_index];
        meminfo.freeram = vm_zone_stat_buf[free_index];
        if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
            meminfo.kernelstack = vm_node_stat_buf[kernelstack_index];
            meminfo.pagetable = vm_node_stat_buf[pagetable_index];
        }else{
            meminfo.kernelstack = vm_zone_stat_buf[kernelstack_index];
            meminfo.pagetable = vm_zone_stat_buf[pagetable_index];
        }
        if (THIS_KERNEL_VERSION >= LINUX(4,14,0)){
            meminfo.slab_rec = vm_node_stat_buf[slab_rec_index];
            meminfo.slab_unrec = vm_node_stat_buf[slab_unrec_index];
        }else{
            meminfo.slab_rec = vm_zone_stat_buf[slab_rec_index];
            meminfo.slab_unrec = vm_zone_stat_buf[slab_unrec_index]; 
        }
        for (int lru = LRU_BASE; lru < NR_LRU_LISTS; lru++){
            pages[lru] = vm_node_stat_buf[lru_base_index + lru];
        }
        FREEBUF(vm_zone_stat_buf);
        FREEBUF(vm_node_stat_buf);
    }else if (symbol_exists("vm_stat")){
        ulong *vm_stat_buf = (ulong *)GETBUF(sizeof(ulong) * vt->nr_vm_stat_items);
        readmem(symbol_value("vm_stat"), KVADDR, vm_stat_buf,sizeof(ulong) * vt->nr_vm_stat_items,"vm_stat", FAULT_ON_ERROR);
        meminfo.sharedram = vm_stat_buf[shmem_index];
        meminfo.freeram = vm_stat_buf[free_index];
        meminfo.swapcache = vm_stat_buf[swapcache_index];
        meminfo.filepages = vm_stat_buf[filepages_index];
        meminfo.slab_rec = vm_stat_buf[slab_rec_index];
        meminfo.slab_unrec = vm_stat_buf[slab_unrec_index]; 
        FREEBUF(vm_stat_buf);
    }
    uint tmp;
    if (symbol_exists("buffermem_pages")) { 
        get_symbol_data("buffermem_pages", sizeof(int), &tmp);
		meminfo.bufferram = (ulong)tmp;
	} else if (symbol_exists("buffermem")) {
        get_symbol_data("buffermem", sizeof(int), &tmp);
		meminfo.bufferram = BTOP(tmp);
	} else if ((THIS_KERNEL_VERSION >= LINUX(2,6,0)) && symbol_exists("nr_blockdev_pages")) {
		meminfo.bufferram = get_blockdev_pages();
	} else{
        meminfo.bufferram = 0;
    }
    if (swapcache_index == 0){
        get_swap_cache(&meminfo);
	}
    if (symbol_exists("_totalhigh_pages")){
        meminfo.totalhigh = mm_read_pointer(symbol_value("_totalhigh_pages"),"_totalhigh_pages");
    }
    meminfo.totalram = mm_read_pointer(symbol_value("_totalram_pages"),"_totalram_pages");
    meminfo.cached = meminfo.filepages - meminfo.swapcache - meminfo.bufferram;
    if (meminfo.cached < 0){
        meminfo.cached = 0;
    }
    sprintf(prefix_buf, "%s", "RAM: ");
    convert_size(total_spanned_pages*PAGESIZE(),size_buf);
    fprintf(fp, "%s%s\n",mkstring(prefix_buf, 29, LJUST,prefix_buf),size_buf);

    ulong sbl_carveout = (total_spanned_pages*PAGESIZE() - mem_total_size);
    sprintf(prefix_buf, "%s", "Carveout: ");
    convert_size(sbl_carveout,size_buf);
    fprintf(fp, "%s%s\n",mkstring(prefix_buf, 29, LJUST,prefix_buf),size_buf);
    if (sbl_carveout >= nomap_size){ 
        sprintf(prefix_buf, "%s", "No-Map: ");
        convert_size(nomap_size,size_buf);
        fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

        ulong other_hole_size = sbl_carveout - nomap_size;
        sprintf(prefix_buf, "%s", "Other: ");
        convert_size(other_hole_size,size_buf);
        fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);
    }
    sprintf(prefix_buf, "%s", "MemTotal: ");
    convert_size(meminfo.totalram*PAGESIZE(),size_buf);
    fprintf(fp, "%s%s\n",mkstring(prefix_buf, 29, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "MemFree: ");
    convert_size(meminfo.freeram*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Buffers: ");
    convert_size(meminfo.bufferram*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Cached: ");
    convert_size(meminfo.cached*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "SwapCached: ");
    convert_size(meminfo.swapcache*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Active: ");
    convert_size((pages[LRU_ACTIVE_ANON] + pages[LRU_ACTIVE_FILE])*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Anon: ");
    convert_size(pages[LRU_ACTIVE_ANON]*PAGESIZE(),size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "File: ");
    convert_size(pages[LRU_ACTIVE_FILE]*PAGESIZE(),size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Inactive: ");
    convert_size((pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE])*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Anon: ");
    convert_size(pages[LRU_INACTIVE_ANON]*PAGESIZE(),size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "File: ");
    convert_size(pages[LRU_INACTIVE_FILE]*PAGESIZE(),size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Slab: ");
    convert_size((meminfo.slab_rec + meminfo.slab_unrec)*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "SReclaimable: ");
    convert_size(meminfo.slab_rec*PAGESIZE(),size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "SUnreclaim: ");
    convert_size(meminfo.slab_unrec*PAGESIZE(),size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "KernelStack: ");
    convert_size(meminfo.kernelstack*1024,size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "PageTables: ");
    convert_size(meminfo.pagetable*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Shmem: ");
    convert_size(meminfo.sharedram*PAGESIZE(),size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Cma: ");
    ulong cma_size = get_cma_size();
    convert_size(cma_size,size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Vmalloc: ");
    ulong vmalloc_size = get_vmalloc_size();
    convert_size(vmalloc_size,size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    sprintf(prefix_buf, "%s", "Dmabuf: ");
    ulong dma_size = get_dma_size();
    convert_size(dma_size,size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    ulong total_reserved_size = mem_total_size - meminfo.totalram*PAGESIZE();
    ulong static_size = total_reserved_size;
    sprintf(prefix_buf, "%s", "Reserved: ");
    convert_size(total_reserved_size,size_buf);
    fprintf(fp, "%s%s\n",mkstring(prefix_buf, 29, LJUST,prefix_buf),size_buf);
    if (sbl_carveout < nomap_size){ 
        sprintf(prefix_buf, "%s", "No-Map: ");
        convert_size(nomap_size,size_buf);
        fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);
        static_size = total_reserved_size - nomap_size;
    }
    sprintf(prefix_buf, "%s", "Static: ");
    convert_size(static_size,size_buf);
    fprintf(fp, "   %s%s\n",mkstring(prefix_buf, 26, LJUST,prefix_buf),size_buf);

    ulong max_pfn = 0;
    ulong min_low_pfn = 0;
    readmem(symbol_value("max_pfn"), KVADDR, &max_pfn, sizeof(ulong), "max_pfn", FAULT_ON_ERROR);
    readmem(symbol_value("min_low_pfn"), KVADDR, &min_low_pfn, sizeof(ulong), "min_low_pfn", FAULT_ON_ERROR);
    ulong total_pfn = max_pfn - min_low_pfn - (sbl_carveout/PAGESIZE()) - (nomap_size/PAGESIZE());
    ulong struct_page_size = total_pfn*struct_size(page);
    sprintf(prefix_buf, "%s", "Struct Page: ");
    convert_size(struct_page_size,size_buf);
    fprintf(fp, "       %s%s(%ld)\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf,total_pfn);

    ulong kernel_code_size = symbol_value("_sinittext") - symbol_value("_text");
    sprintf(prefix_buf, "%s", "Kernel Code: ");
    convert_size(kernel_code_size,size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);

    ulong kernel_data_size = symbol_value("_end") - symbol_value("_sdata");
    sprintf(prefix_buf, "%s", "Kernel Data: ");
    convert_size(kernel_data_size,size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);
    ulong dentry_size = 0;
    if (symbol_exists("d_hash_shift")) { 
        uint d_hash_shift;
        get_symbol_data("d_hash_shift", sizeof(int), &d_hash_shift);
        d_hash_shift = 32 - d_hash_shift;
        dentry_size = struct_size(hlist_bl_head) << d_hash_shift;
        sprintf(prefix_buf, "%s", "Dentry cache: ");
        convert_size(dentry_size,size_buf);
        fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);
    }
    ulong inode_size = 0;
    if (symbol_exists("i_hash_shift")) { 
        uint i_hash_shift;
        get_symbol_data("i_hash_shift", sizeof(int), &i_hash_shift);
        i_hash_shift = 32 - i_hash_shift;
        inode_size = struct_size(hlist_head) << i_hash_shift;
        sprintf(prefix_buf, "%s", "Inode cache: ");
        convert_size(inode_size,size_buf);
        fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);
    }
    ulong other_size = static_size - struct_page_size - kernel_code_size - kernel_data_size - dentry_size - inode_size;
    sprintf(prefix_buf, "%s", "Other: ");
    convert_size(other_size,size_buf);
    fprintf(fp, "       %s%s\n",mkstring(prefix_buf, 22, LJUST,prefix_buf),size_buf);
    fprintf(fp, "====================================================\n");
}

void convert_size(ulong size,char* buf){
    if (size < 1024){
        sprintf(buf, "%ldB",size);
    }else if (size < 1024 * 1024){
        sprintf(buf, "%.2fKB",(float)size/1024);
    }else if (size < 1024 * 1024 * 1024){
        sprintf(buf, "%.2fMB",(float)size/1024/1024);
    }else{
        sprintf(buf, "%.2fGB",(float)size/1024/1024/1024);
    }
}

void get_swap_cache(struct sysinfo* meminfo){
    int len = 0;
    char *address_space_buf = GETBUF(struct_size(address_space));
    if (symbol_exists("nr_swapper_spaces") && (len = get_array_length("nr_swapper_spaces",NULL, 0))) {
        char *nr_swapper_space = GETBUF(len * sizeof(unsigned int));
        readmem(symbol_value("nr_swapper_spaces"), KVADDR, nr_swapper_space,  len * sizeof(unsigned int),"nr_swapper_space", RETURN_ON_ERROR);
        for (int i = 0; i < len; i++) {
            int j;
            unsigned long swapper_spaces_addr;
            unsigned int banks = UINT(nr_swapper_space + (i * sizeof(unsigned int)));
            if (!banks)continue;
            readmem(symbol_value("swapper_spaces") + (i * sizeof(void *)),KVADDR, &swapper_spaces_addr, sizeof(void *),"swapper_space", RETURN_ON_ERROR);
            if (!swapper_spaces_addr)
                continue;
            for (j = 0; j < banks; j++) {
                if (!readmem(swapper_spaces_addr + j * struct_size(address_space),KVADDR, address_space_buf,struct_size(address_space),"swapper_space",RETURN_ON_ERROR))
                    break;
                meminfo->swapcache += ULONG(address_space_buf + field_offset(address_space,nrpages));
            }
        }
        FREEBUF(nr_swapper_space);
    } else if (symbol_exists("swapper_spaces") && (len = get_array_length("swapper_spaces", NULL, 0))) {
        fprintf(fp, "len:%d\n",len);
        for (int i = 0; i < len; i++) {
            if (!readmem(symbol_value("swapper_spaces") + i * struct_size(address_space),KVADDR, address_space_buf,struct_size(address_space),"swapper_space",RETURN_ON_ERROR))
                break;
            meminfo->swapcache += ULONG(address_space_buf + field_offset(address_space,nrpages));
        }
    } else if (symbol_exists("swapper_space") && readmem(symbol_value("swapper_space"), KVADDR, address_space_buf, struct_size(address_space), "swapper_space", RETURN_ON_ERROR)){
        meminfo->swapcache = ULONG(address_space_buf + field_offset(address_space,nrpages));
    }
    FREEBUF(address_space_buf);
}

ulong get_blockdev_pages(void){
    ulong total_nr_pages = 0;
    if (!kernel_symbol_exists("all_bdevs")){
        ulong* inode_buf = NULL;
        int offset = field_offset(inode,i_sb_list);
        ulong superblock = mm_read_pointer(symbol_value("blockdev_superblock"),"blockdev_superblock");
        ulong list_head = superblock + field_offset(super_block,s_inodes);
        int inodecnt = mm_for_each_list_entry(list_head,offset,&inode_buf);
        for (int i = 0; i < inodecnt; ++i) {
            ulong inode_addr = inode_buf[i];
            if (inode_addr <= 0) continue;
            ulong i_mapping = mm_read_pointer(inode_addr + field_offset(inode,i_mapping),"inode_i_mapping");
            if (i_mapping <= 0) continue;
            void *address_space_buf = mm_read_struct(i_mapping,struct_size(address_space),"address_space");
            if(address_space_buf == NULL)continue;
            ulong nrpages = ULONG(address_space_buf + field_offset(address_space,nrpages));
            total_nr_pages += nrpages;
            FREEBUF(address_space_buf);
        }
        FREEBUF(inode_buf);
    }else{
        ulong* bd_buf = NULL;
        int offset = field_offset(block_device,bd_list);
        int bdevcnt = mm_for_each_list_entry(symbol_value("all_bdevs"),offset,&bd_buf);
        for (int i = 0; i < bdevcnt; ++i) {
            ulong bd_addr = bd_buf[i];
            if (bd_addr <= 0) continue;
            ulong bd_inode = mm_read_pointer(bd_addr + field_offset(block_device,bd_inode),"block_device_bd_inode");
            if (bd_inode <= 0) continue;
            ulong i_mapping = mm_read_pointer(bd_inode + field_offset(inode,i_mapping),"inode_i_mapping");
            if (i_mapping <= 0) continue;
            void *address_space_buf = mm_read_struct(i_mapping,struct_size(address_space),"address_space");
            if(address_space_buf == NULL)continue;
            ulong nrpages = ULONG(address_space_buf + field_offset(address_space,nrpages));
            total_nr_pages += nrpages;
            FREEBUF(address_space_buf);
        }
        FREEBUF(bd_buf);
    }
    return total_nr_pages;
} 

void get_reserved_mem(ulong* total_size,ulong* nomap_size,ulong* reusable_size){
    if (!symbol_exists("reserved_mem")){
        error(FATAL, "reserved_mem doesn't exist in this kernel!\n");
        return;
    }
    ulong reserved_mem_addr = symbol_value("reserved_mem");
    if (!reserved_mem_addr) return;
    ulong reserved_mem_count = mm_read_pointer(symbol_value("reserved_mem_count"),"reserved_mem_count");
    for (int i = 0; i < reserved_mem_count; ++i) {
        ulong reserved_addr = reserved_mem_addr + i * struct_size(reserved_mem);
        void *reserved_mem_buf = mm_read_struct(reserved_addr,struct_size(reserved_mem),"reserved_mem");
        if(reserved_mem_buf == NULL) return;
        char name[64];
        mm_read_cstring(ULONG(reserved_mem_buf + field_offset(reserved_mem,name)),name,64, "reserved_mem_name");
        ulong node = mm_find_node_by_name(name);
        if (node == 0)continue;
        void *node_buf = mm_read_struct(node,struct_size(device_node),"device_node");
        if(node_buf == NULL)continue;
        ulong properties = ULONG(node_buf + field_offset(device_node,properties));
        FREEBUF(node_buf);
        if (properties == 0)continue;     
        bool is_nomap = mm_has_prop_name(properties,"no-map");
        bool is_reusable = mm_has_prop_name(properties,"reusable");
        int CONFIG_PHYS_ADDR_T_64BIT = get_kernel_config("CONFIG_PHYS_ADDR_T_64BIT", NULL);
        if(CONFIG_PHYS_ADDR_T_64BIT){
            ulonglong size = ULONGLONG(reserved_mem_buf + field_offset(reserved_mem,size));
            *total_size += size;
            if (is_nomap){
                *nomap_size += size;
            }else if (is_reusable){
                *reusable_size += size;
            }
        }else{
            ulong size = ULONG(reserved_mem_buf + field_offset(reserved_mem,size));
            *total_size += size;
            if (is_nomap){
                *nomap_size += size;
            }else if (is_reusable){
                *reusable_size += size;
            }
        }
        FREEBUF(reserved_mem_buf);
    }
}

void parser_buddy_info(){
	int n, m, z, o;
	int list_count = 0;
	ulong free_cnt = 0;
	int mtype_sym = 0;
	int mtype_len = 0;
	ulong *mtypes;
	ulong node_zones;
	ulong temp;
	ulong freelist;
	ulong *free_ptr;
	char *free_list_buf;
	char name_buf[BUFSIZE];
	char buf[BUFSIZE];
	struct node_table *nt;
	struct list_data list_data;
	if (!(vt->flags & (NODES|ZONES)))
		error(FATAL,"dump_pgtype_info called without (NODES|ZONES)\n");

	if (!VALID_STRUCT(zone))
		error(FATAL,"zone struct not available in this kernel\n");

	if (VALID_STRUCT(free_area)) {
		if (SIZE(free_area) == (3 * sizeof(ulong)))
			error(FATAL,"free_area type not supported by command\n");
		else
			list_count = MEMBER_SIZE("free_area","free_list")/SIZE(list_head);
	} else
		error(FATAL,"free_area structure not found in this kernel\n");
	free_list_buf = GETBUF(SIZE(list_head));
	do {
		if (symbol_exists("migratetype_names") && (get_symbol_type("migratetype_names",NULL, NULL) == TYPE_CODE_ARRAY)) {
			open_tmpfile();
			sprintf(buf, "whatis migratetype_names");
			if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
				close_tmpfile();
				break;
			}
			rewind(pc->tmpfile);
			while (fgets(buf, BUFSIZE, pc->tmpfile)) {
				if (STRNEQ(buf, "type = "))
					break;
			}
			close_tmpfile();
			if (!strstr(buf, "char *") ||
				(count_chars(buf, '[') != 1) ||
				(count_chars(buf, ']') != 1))
				break;
			mtype_len = get_array_length("migratetype_names",NULL, 0);
			mtypes = (ulong *)GETBUF(mtype_len * sizeof(ulong));
			readmem(symbol_value("migratetype_names"),KVADDR, mtypes,(mtype_len * sizeof(ulong)),NULL, FAULT_ON_ERROR);
			mtype_sym = 1;
		}
	} while (0);

	fprintf(fp, "%-43s [%d-%d]:","Free pages count per migrate type at order",0, vt->nr_free_areas - 1);
	fprintf(fp, "\n");
	for (n = 0; n < vt->numnodes; n++) {
		nt = &vt->node_table[n];
		fprintf(fp, "Node(%d) \n", nt->node_id);
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);
		for (z = 0; z < vt->nr_zones; z++) {
			ulong zone_addr = (node_zones + (z * SIZE(zone)));
			fprintf(fp, "-----------------------------------------------------------------------------------------------------\n");
			readmem(zone_addr + OFFSET(zone_name), KVADDR, &temp,sizeof(void *), "node_zones name",FAULT_ON_ERROR);
			read_string(temp, name_buf, BUFSIZE-1);
			fprintf(fp, "			         zone %s \n", name_buf);
			fprintf(fp, "-----------------------------------------------------------------------------------------------------\n");
			fprintf(fp, "%12s ", "Order");
			for (o = 0; o < vt->nr_free_areas; o++) { //order
				char order[BUFSIZE];
				sprintf(order, "%dK", (1U << o)*PAGESIZE()/1024);
				fprintf(fp, "%6s ", order);
			}
			fprintf(fp, "%8s\n", "Total");
            char size_buf[BUFSIZE];
			for (m = 0; m < list_count; m++) { //migrate type
				if (mtype_sym) {
					read_string(mtypes[m],name_buf, BUFSIZE-1);
					fprintf(fp, "%12s ", name_buf);
				} else
					fprintf(fp, "%12d ", m);
				int total_size = 0;
				for (o = 0; o < vt->nr_free_areas; o++) { //order
					ulong free_area_addr = zone_addr + (OFFSET(zone_free_area) + (o * SIZE(free_area)));
					freelist = free_area_addr + (m * SIZE(list_head));
					readmem(freelist, KVADDR, free_list_buf,SIZE(list_head),"free_area free_list",FAULT_ON_ERROR);
					free_ptr = (ulong *)free_list_buf;
					if (!(*free_ptr) || (*free_ptr == freelist)) {
						fprintf(fp, "%6lu ", (ulong)0);
						continue;
					}
					BZERO(&list_data,sizeof(struct list_data));
					list_data.flags = RETURN_ON_DUPLICATE;
					list_data.start = *free_ptr;
					list_data.end = freelist;
					list_data.list_head_offset = OFFSET(page_lru) + OFFSET(list_head_next);
					free_cnt = do_list(&list_data);
					if (free_cnt < 0) {
						error(pc->curcmd_flags & IGNORE_ERRORS ? INFO : FATAL, "corrupted free list\n");
						free_cnt = 0;
					}
					fprintf(fp, "%6lu ", free_cnt);
					total_size += (1U << o)*PAGESIZE()*free_cnt;
				}
                convert_size(total_size,size_buf);
				fprintf(fp, "%8s\n", size_buf);
			}
			fprintf(fp, "-----------------------------------------------------------------------------------------------------\n\n\n");
		}
		fprintf(fp, "\n");
	}
	FREEBUF(free_list_buf);
	if (mtype_sym)
		FREEBUF(mtypes);
}

void parser_dma_buf(){
    if (!symbol_exists("db_list")){
        error(FATAL, "db_list doesn't exist in this kernel!\n");
        return;
    }
    ulong db_list_addr = symbol_value("db_list");
    if (!db_list_addr) return;
    ulong* dma_buf_data = NULL;
    int total_size = 0;
    int offset = field_offset(dma_buf,list_node);
    int cnt = mm_for_each_list_entry(db_list_addr,offset,&dma_buf_data);
    fprintf(fp, "==============================================================================================================\n");
    for (int i = 0; i < cnt; ++i) {
        ulong dma_buf_addr = dma_buf_data[i];
        if (dma_buf_addr <= 0) continue;
        void *dma_buf = mm_read_struct(dma_buf_addr,struct_size(dma_buf),"dma_buf");
        if(dma_buf == NULL) return;
        int size = INT(dma_buf + field_offset(dma_buf,size));
        total_size += size;
        ulong priv = ULONG(dma_buf + field_offset(dma_buf,priv));
        ulong file = ULONG(dma_buf + field_offset(dma_buf,file));
        void *file_buf = mm_read_struct(file,struct_size(file),"file");
        int f_count = INT(file_buf + field_offset(file,f_count));
        FREEBUF(file_buf);
        // char name[64];
        // ulong name_addr = ULONG(dma_buf + field_offset(dma_buf,name));
        // if (name_addr > 0){
        //     mm_read_cstring(name_addr,name,64, "dma_buf_name");
        // }
        char exp_name[64];
        ulong exp_name_addr = ULONG(dma_buf + field_offset(dma_buf,exp_name));
        if (exp_name_addr > 0){
            mm_read_cstring(exp_name_addr,exp_name,64, "dma_buf_exp_name");
        }
        char buf_size[BUFSIZE];
        sprintf(buf_size, "%dK", size/1024);
        fprintf(fp, "[%d]dma_buf:0x%lx [%s] priv:0x%lx f_count:%d size:%s\n",i,dma_buf_addr,exp_name,
            priv,f_count,mkstring(buf_size, 9, LJUST,buf_size));
        ulong attachments_head = dma_buf_addr + field_offset(dma_buf,attachments);
        parser_dma_buf_attachment(attachments_head);
        FREEBUF(dma_buf);
    }
    fprintf(fp, "==============================================================================================================\n");
    fprintf(fp, "total dma_buf size:%.2fM\n",((float)total_size/1024/1024));
    if(dma_buf_data != NULL)FREEBUF(dma_buf_data);
}

void parser_dma_buf_attachment(ulong addr){
    ulong* attachment_buf_data = NULL;
    int offset = field_offset(dma_buf_attachment,node);
    int cnt = mm_for_each_list_entry(addr,offset,&attachment_buf_data);
    for (int i = 0; i < cnt; ++i) {
        ulong attachment_addr = attachment_buf_data[i];
        if (attachment_addr <= 0) continue;
        void *dma_buf_attachment = mm_read_struct(attachment_addr,struct_size(dma_buf_attachment),"dma_buf_attachment");
        if(dma_buf_attachment == NULL) return;
        ulong dev_addr = ULONG(dma_buf_attachment + field_offset(dma_buf_attachment,dev));
        ulong driver_addr = 0;
        char device_name[64] = "unknow";
        char driver_name[64] = "unknow";
        if(dev_addr > 0){
            void *device_buf = mm_read_struct(dev_addr,struct_size(device),"device");
            if(device_buf == NULL) return;
            ulong device_name_addr = ULONG(device_buf);
            driver_addr = ULONG(device_buf + field_offset(device,driver));
            FREEBUF(device_buf);
            if (device_name_addr > 0){
                mm_read_cstring(device_name_addr,device_name,64, "device_name");
            }
            if (driver_addr > 0){
                ulong driver_name_addr = mm_read_pointer(driver_addr,"driver_name");
                mm_read_cstring(driver_name_addr,driver_name,64, "driver_name");
            }
        }
        ulong priv = ULONG(dma_buf_attachment + field_offset(dma_buf_attachment,priv));
        fprintf(fp, "   dma_buf_attachment:0x%lx device:0x%lx[%s] driver:0x%lx[%s] priv:0x%lx\n",
            attachment_addr,dev_addr,device_name,driver_addr,driver_name,priv);
        FREEBUF(dma_buf_attachment);
    }
    if(attachment_buf_data != NULL)FREEBUF(attachment_buf_data);
    fprintf(fp, "\n");
}

void parser_mem_block(){
    if (!symbol_exists("memblock")){
        error(FATAL, "memblock doesn't exist in this kernel!\n");
        return;
    }
    ulong memblock_addr = symbol_value("memblock");
    if (!memblock_addr) return;
    ulong memblock_type_memory_addr = memblock_addr + field_offset(memblock,memory);
    parser_memblock_type(memblock_type_memory_addr);
    ulong memblock_type_reserved_addr = memblock_addr + field_offset(memblock,reserved);
    parser_memblock_type(memblock_type_reserved_addr);
}

void parser_memblock_type(ulong addr){
    char buf[BUFSIZE];
    void *memblock_type_buf = mm_read_struct(addr,struct_size(memblock_type),"memblock_type");
    if(memblock_type_buf == NULL) return;
    ulong cnt = ULONG(memblock_type_buf + field_offset(memblock_type,cnt));
    // ulong max = ULONG(memblock_type_buf + field_offset(memblock_type,max));
    int CONFIG_PHYS_ADDR_T_64BIT = get_kernel_config("CONFIG_PHYS_ADDR_T_64BIT", NULL);
    ulong total_size = 0;
    if(CONFIG_PHYS_ADDR_T_64BIT){
        total_size = (ulong)ULONGLONG(memblock_type_buf + field_offset(memblock_type,total_size));
    }else{
        total_size = ULONG(memblock_type_buf + field_offset(memblock_type,total_size));
    }
    ulong regions = ULONG(memblock_type_buf + field_offset(memblock_type,regions));
    char name[64];
    mm_read_cstring(ULONG(memblock_type_buf + field_offset(memblock_type,name)),name,64, "memblock_type_name");
    convert_size(total_size,buf);
    fprintf(fp, "memblock_type:0x%lx [%s] size:%s\n",addr,name,buf);
    FREEBUF(memblock_type_buf);
    for (int i = 0; i < cnt; ++i) {
        ulong region_addr = regions + i * struct_size(memblock_region);
        void *memblock_region_buf = mm_read_struct(region_addr,struct_size(memblock_region),"memblock_region");
        if(memblock_region_buf == NULL) return;
        ulong base = 0;
        ulong size = 0;
        if(CONFIG_PHYS_ADDR_T_64BIT){
            base = (ulong)ULONGLONG(memblock_region_buf + field_offset(memblock_region,base));
            size = (ulong)ULONGLONG(memblock_region_buf + field_offset(memblock_region,size));
        }else{
            base = ULONG(memblock_region_buf + field_offset(memblock_region,base));
            size = ULONG(memblock_region_buf + field_offset(memblock_region,size));
        }
        int flags = INT(memblock_region_buf + field_offset(memblock_region,flags));
        sprintf(buf, "  [%d]",i);
        fprintf(fp, "%s ",mkstring(buf, 6, LJUST, buf));
        fprintf(fp, "memblock_region:0x%lx ",region_addr);
        sprintf(buf, "range:0x%lx~0x%lx ",base,(base+size));
        fprintf(fp, "%s ",mkstring(buf, 35, LJUST, buf));
        convert_size(size,buf);
        fprintf(fp, "size:%s ",mkstring(buf, 10, LJUST,buf));
        fprintf(fp, "flags:%s\n",memblock_flags_str[flags]);
        FREEBUF(memblock_region_buf);
    }
    fprintf(fp, "\n");
}

void parser_reserved_mem(){
    if (!symbol_exists("reserved_mem")){
        error(FATAL, "reserved_mem doesn't exist in this kernel!\n");
        return;
    }
    ulong reserved_mem_addr = symbol_value("reserved_mem");
    if (!reserved_mem_addr) return;
    ulong total_size = 0;
    ulong nomap_size = 0;
    ulong reusable_size = 0;
    ulong other_size = 0;
    char buf[BUFSIZE];
    ulong reserved_mem_count = mm_read_pointer(symbol_value("reserved_mem_count"),"reserved_mem_count");
    fprintf(fp, "==============================================================================================================\n");
    for (int i = 0; i < reserved_mem_count; ++i) {
        ulong reserved_addr = reserved_mem_addr + i * struct_size(reserved_mem);
        void *reserved_mem_buf = mm_read_struct(reserved_addr,struct_size(reserved_mem),"reserved_mem");
        if(reserved_mem_buf == NULL) return;
        // ulong fdt_node = ULONG(reserved_mem_buf + field_offset(reserved_mem,fdt_node));
        // ulong phandle = ULONG(reserved_mem_buf + field_offset(reserved_mem,phandle));
        // read name
        char name[64];
        mm_read_cstring(ULONG(reserved_mem_buf + field_offset(reserved_mem,name)),name,64, "reserved_mem_name");
        ulong node = mm_find_node_by_name(name);
        if (node == 0){
            continue;
        }
        void *node_buf = mm_read_struct(node,struct_size(device_node),"device_node");
        if(node_buf == NULL){
            continue;
        }
        ulong properties = ULONG(node_buf + field_offset(device_node,properties));
        FREEBUF(node_buf);
        if (properties == 0){
            continue;     
        }
        bool is_nomap = mm_has_prop_name(properties,"no-map");
        bool is_reusable = mm_has_prop_name(properties,"reusable");
        ulonglong base = 0;
        ulonglong size = 0;
        ulonglong end = 0;
        int CONFIG_PHYS_ADDR_T_64BIT = get_kernel_config("CONFIG_PHYS_ADDR_T_64BIT", NULL);
        if(CONFIG_PHYS_ADDR_T_64BIT){
            base = ULONGLONG(reserved_mem_buf + field_offset(reserved_mem,base));
            size = ULONGLONG(reserved_mem_buf + field_offset(reserved_mem,size));
        }else{
            base = ULONG(reserved_mem_buf + field_offset(reserved_mem,base));
            size = ULONG(reserved_mem_buf + field_offset(reserved_mem,size));
        }
        end = base + size;
        total_size += size;
        sprintf(buf, "[%d]",i);
        fprintf(fp, "%s ",mkstring(buf, 4, LJUST, buf));
        fprintf(fp, "%s ",mkstring(buf, 37, LJUST, name));
        fprintf(fp, "reserved_mem:0x%lx ",reserved_addr);
        sprintf(buf, "range:0x%llx~0x%llx ",base,end);
        fprintf(fp, "%s ",mkstring(buf, 30, LJUST, buf));
        convert_size(size,buf);
        fprintf(fp, "size:%s ",mkstring(buf, 10, LJUST,buf));
        if (is_nomap){
            sprintf(buf, "%s", "no-map");
            nomap_size += size;
        }else if (is_reusable){
            sprintf(buf, "%s", "reusable");
            reusable_size += size;
        }else{
            sprintf(buf, "%s", "unknow");
            other_size += size;
        }
        fprintf(fp, "[%s]\n",buf);
        FREEBUF(reserved_mem_buf);
    }
    fprintf(fp, "==============================================================================================================\n");
    convert_size(total_size,buf);
    fprintf(fp, "Total:%s ",buf);
    convert_size(nomap_size,buf);
    fprintf(fp, "nomap:%s ",buf);
    convert_size(reusable_size,buf);
    fprintf(fp, "reuse:%s ",buf);
    convert_size(other_size,buf);
    fprintf(fp, "other:%s\n",buf);
}

void parser_cma_areas(){
    if (!symbol_exists("cma_areas")){
        error(FATAL, "cma_areas doesn't exist in this kernel!\n");
        return;
    }
    char buf[BUFSIZE];
    ulong cma_areas_addr = symbol_value("cma_areas");
    if (!cma_areas_addr) return;
    ulong cma_area_count = mm_read_pointer(symbol_value("cma_area_count"),"cma_area_count");
    // ulong totalcma_pages = mm_read_pointer(symbol_value("totalcma_pages"),"totalcma_pages");
    ulong totalcma_pages = 0;
    ulong total_use = 0;
    fprintf(fp, "==============================================================================================================\n");
    for (int i = 0; i < cma_area_count; ++i) {
        ulong cma_addr = cma_areas_addr + i * struct_size(cma);
        void *cma_buf = mm_read_struct(cma_addr,struct_size(cma),"cma");
        if(cma_buf == NULL) return;
        ulong base_pfn = ULONG(cma_buf + field_offset(cma,base_pfn));
        ulong count = ULONG(cma_buf + field_offset(cma,count));
        ulong bitmap = ULONG(cma_buf + field_offset(cma,bitmap));
        int order_per_bit = UINT(cma_buf + field_offset(cma,order_per_bit));
        // read cma name
        char cma_name[64];
        if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
            memcpy(&cma_name,cma_buf + field_offset(cma,name),64);
        }else{
            ulong name_addr = ULONG(cma_buf + field_offset(cma,name));
            mm_read_cstring(name_addr,cma_name,64, "cma_name");
        }
        ulong allocated_size = get_cma_used_size(bitmap,count,order_per_bit);
        totalcma_pages += count;
        total_use += allocated_size;
        sprintf(buf, "[%d]",i);
        fprintf(fp, "%s ",mkstring(buf, 4, LJUST, buf));
        fprintf(fp, "%s ",mkstring(buf, 37, LJUST, cma_name));
        fprintf(fp, "cma:0x%lx ",cma_addr);
        sprintf(buf, "PFN:0x%lx~0x%lx ",base_pfn,(base_pfn + count));
        fprintf(fp, "%s ",mkstring(buf, 25, LJUST, buf));
        convert_size(count * PAGESIZE(),buf);
        fprintf(fp, "size:%s ",mkstring(buf, 10, LJUST,buf));
        convert_size(allocated_size,buf);
        fprintf(fp, "used:%s ",mkstring(buf, 10, LJUST,buf));
        fprintf(fp, "order:%d\n",order_per_bit);
        FREEBUF(cma_buf);
    }
    fprintf(fp, "==============================================================================================================\n");
    convert_size(totalcma_pages * PAGESIZE(),buf);
    fprintf(fp, "Total:%s ",buf);
    convert_size(total_use,buf);
    fprintf(fp, "allocated:%s\n",buf);
}

int get_cma_used_size(ulong bitmap_addr, ulong nr_pages,int order){
    // calc how many byte of bitmap
    ulong nr_byte = (nr_pages >> order) / 8 / sizeof(void *);
    int per_bit_size = (1U << order) * PAGESIZE();
    // fprintf(fp, "nr_byte:%ld\n",nr_byte);
    // fprintf(fp, "per_bit_size:%ld\n",per_bit_size);
    int used_count = 0;
    for (int i = 0; i < nr_byte; ++i) {
        ulong bitmap_data = mm_read_pointer(bitmap_addr,"cma bitmap");
        int nr_bit = count_ones_in_byte(bitmap_data);
        // fprintf(fp, "bitmap_addr:0x%lx bitmap:%lx, nr_bit:%d\n",bitmap_addr, bitmap_data, nr_bit);
        used_count += nr_bit;
        bitmap_addr += sizeof(void *);
    }
    // fprintf(fp, "used_count:%ld\n",used_count);
    return (used_count * per_bit_size);
}

int count_ones_in_byte(ulong value) {
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

void parser_vmap_area_list(){
    if (!symbol_exists("vmap_area_list")){
        error(FATAL, "vmap_area_list doesn't exist in this kernel!\n");
        return;
    }
    ulong vmap_area_list = symbol_value("vmap_area_list");
    if (!vmap_area_list) return;
    // read all vmap_area
    ulong* vmap_area_data = NULL;
    physaddr_t paddr;
    int total_page_cnt = 0;
    AutoArray vmap_array = initArray();
    int offset = field_offset(vmap_area,list);
    int cnt = mm_for_each_list_entry(vmap_area_list,offset,&vmap_area_data);
    for (int i = 0; i < cnt; ++i) {
        ulong vmap_area_addr = vmap_area_data[i];
        if (vmap_area_addr <= 0) continue;
        struct vmap_area vmap_area;
        readmem(vmap_area_addr, KVADDR, &vmap_area, sizeof(struct vmap_area), "vmap_area", FAULT_ON_ERROR);
        ulong varea_size = vmap_area.va_end - vmap_area.va_start;
        if (vmap_area.va_start == 0 || vmap_area.va_start == 0 || varea_size == 0) continue;
        fprintf(fp, "vmap_area:0x%lx range:0x%lx~0x%lx size:%ldK\n",vmap_area_addr,vmap_area.va_start,vmap_area.va_end,varea_size/1024);
        ulong vm_addr = (ulong)vmap_area.vm;
        while (vm_addr > 0)
        {
            void *vm_struct_buf = mm_read_struct(vm_addr,struct_size(vm_struct),"vm_struct");
            if(vm_struct_buf == NULL) return;
            ulong next = ULONG(vm_struct_buf + field_offset(vm_struct,next));
            ulong addr = ULONG(vm_struct_buf + field_offset(vm_struct,addr));
            ulong size = ULONG(vm_struct_buf + field_offset(vm_struct,size));
            ulong flags = ULONG(vm_struct_buf + field_offset(vm_struct,flags));
            ulong pages = ULONG(vm_struct_buf + field_offset(vm_struct,pages));
            int nr_pages = UINT(vm_struct_buf + field_offset(vm_struct,nr_pages));
            ulong phys_addr = ULONG(vm_struct_buf + field_offset(vm_struct,phys_addr));
            ulong caller = ULONG(vm_struct_buf + field_offset(vm_struct,caller));
            FREEBUF(vm_struct_buf);
            char* flags_str = "unknow";
            if (flags & VM_IOREMAP){
                flags_str = "ioremap";
            }else if (flags & VM_ALLOC){
                flags_str = "vmalloc";
            }else if (flags & VM_MAP){
                flags_str = "vmap";
            }else if (flags & VM_USERMAP){
                flags_str = "user";
            }else if (flags & VM_VPAGES){
                flags_str = "vpages";
            }else if (flags & VM_UNLIST){
                flags_str = "unlist";
            }
            struct syment *sp;
            ulong offset;
            char stack[BUFSIZE];
            if (sp = value_search(caller, &offset)) {
                if (offset)
                        sprintf(stack, "%s+%ld",sp->name, offset);
                else
                        sprintf(stack, "%s", sp->name);
                add_array_entry(&vmap_array, sp->name, nr_pages);
            }
            fprintf(fp, "   vm_struct:0x%lx size:%ldK flags:%s nr_pages:%d addr:0x%lx phys_addr:0x%lx %s\n",
                    vm_addr,size/1024,flags_str,nr_pages,addr,phys_addr,stack);
            ulong page_addr = 0;
            ulong vm_struct_page = 0;
            for (int j = 0; j < nr_pages; ++j) {
                page_addr = pages + j * sizeof(void *);
                paddr = 0;
                vm_struct_page = 0;
                if (!readmem(page_addr, KVADDR, &vm_struct_page, sizeof(void *), "vm_struct pages", RETURN_ON_ERROR|QUIET)) {
                    continue;
                }
                if (vm_struct_page <= 0)
                    continue;
                total_page_cnt += 1;
                is_page_ptr(vm_struct_page, &paddr);
                if (paddr <= 0)
                    continue;
                fprintf(fp, "       Page:0x%lx PA:0x%llx\n",vm_struct_page,(ulonglong)paddr);
            }
            vm_addr = next;
        }
        fprintf(fp, "\n");
    }
    fprintf(fp, "==============================================================================================================\n");
    char buf1[BUFSIZE];
    for (int i = 0; i < vmap_array.count; ++i) {
        struct caller_module* entry = (struct caller_module*)vmap_array.data[i];
        fprintf(fp, "%s Size:%dK\n",mkstring(buf1, 35, LJUST, entry->caller), entry->nr_pages * PAGESIZE()/1024);
    }
    fprintf(fp, "==============================================================================================================\n");
    fprintf(fp, "total vmalloc size:%dK\n",total_page_cnt*PAGESIZE()/1024);
    if(vmap_area_data != NULL)FREEBUF(vmap_area_data);
    freeArray(&vmap_array);
}

AutoArray initArray() {
    AutoArray arr = {NULL, 0, 0};
    arr.data = (ulong*)malloc(INITIAL_CAPACITY * sizeof(ulong));
    if (arr.data == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    arr.count = 0;
    arr.capacity = INITIAL_CAPACITY;
    return arr;
}

void add_array_entry(AutoArray* arr, char* caller, int nr_page) {
    if (arr->count >= arr->capacity) {
        int newCapacity = arr->capacity * 2;
        ulong* newData = (ulong*)realloc(arr->data, newCapacity * sizeof(ulong));
        if (newData == NULL) {
            fprintf(stderr, "Memory reallocation failed.\n");
            freeArray(arr);
            exit(EXIT_FAILURE);
        }
        arr->data = newData;
        arr->capacity = newCapacity;
    }
    // find 
    struct caller_module* res = NULL;
    for (int i = 0; i < arr->count; ++i) {
        struct caller_module* entry = (struct caller_module*)arr->data[i];
        if (!strcmp(entry->caller, caller)) { //same
            res = entry;
            break;
        }
    }
    if (res == NULL){
        res = malloc(sizeof(struct caller_module));
        sprintf(res->caller, "%s", caller);
        res->nr_pages = nr_page;
        arr->data[arr->count] = (ulong)res;
        arr->count += 1;
    }else{
        res->nr_pages += nr_page;
    }
}

void freeArray(AutoArray* arr) {
    for (int i = 0; i < arr->count; ++i) {
        free((void*)arr->data[i]);
    }
    free(arr->data);
    arr->data = NULL;
    arr->capacity = arr->count = 0;
}

void* mm_read_struct(ulong kvaddr,int size, char* name){
    void* buf = (void *)GETBUF(size);
    if (!readmem(kvaddr, KVADDR, buf, size, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name,kvaddr);
        FREEBUF(buf);
        return NULL;
	}
    return buf;
}

ulong mm_read_pointer(ulong kvaddr,char* name){
    ulong val;
    if (!readmem(kvaddr, KVADDR, &val, sizeof(void *), name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, kvaddr);
        return -1;
	}
    return val;
}

void* mm_read_structure_field(ulong kvaddr,int offset, int size, char* name){
    ulong addr = kvaddr + offset;
    void *buf = (void *)GETBUF(size);
    if (!readmem(addr, KVADDR, buf, size, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, addr);
        FREEBUF(buf);
        return NULL;
	}
    return buf;
}

void mm_read_cstring(ulong kvaddr,char* buf, int len, char* name){
    if (!readmem(kvaddr, KVADDR, buf, len, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, kvaddr);
	}
}

int mm_for_each_hlist_entry(ulong hlist_head,int offset,ulong **ptr){
    ulong first = mm_read_pointer(hlist_head,"hlist_head");
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    ld.start = first;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return 0;
    int cnt = do_list(&ld);
    if(cnt==0)return 0;
    *ptr = ld.list_ptr;
    return cnt;
}

int mm_for_each_list_entry(ulong list_head,int offset,ulong **ptr){
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    readmem(list_head, KVADDR, &ld.start,sizeof(ulong), "mm_for_each_list_entry list_head", FAULT_ON_ERROR);
    ld.end = list_head;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return 0;
    int cnt = do_list(&ld);
    if(cnt==0)return 0;
    *ptr = ld.list_ptr;
    return cnt;
}

int mm_for_each_rbtree_entry(ulong rb_root,int offset,ulong **ptr){
    ulong *treeList;
    struct tree_data td;
    int cnt = 0;
    BZERO(&td, sizeof(struct tree_data));
    // td.flags |= VERBOSE | TREE_POSITION_DISPLAY | TREE_LINEAR_ORDER;
    td.flags |= TREE_NODE_POINTER;
    td.start = rb_root;
    td.node_member_offset = offset;
    hq_open();
    cnt = do_rbtree(&td);
    if(cnt==0)return 0;
    treeList = (ulong *)GETBUF(cnt * sizeof(void *));
    retrieve_list(treeList, cnt);
    for (int i = 0; i < cnt; ++i) {
        if (treeList[i] <= 0) continue;
        // fprintf(fp, "node addr:%lx\n",treeList[i]);
        treeList[i] -= td.node_member_offset;
        *ptr = treeList;
    }
    hq_close();
    return cnt;
}
