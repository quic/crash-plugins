// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "devicetree.h"

static void dts_init(void);
static void dts_fini(void);
static void cmd_dts(void);

char *help_dts[] = {
	"dts",							/* command name */
	"dump dts info",		/* short description */
	"-a \n"
    "  dts -f\n"
    "  dts -b\n"
    "  dts -n <name>\n"
    "  dts -p <full path>\n"
    "  dts -s\n"			       
	"  This command dumps the dts info.",
    "\n",
    "EXAMPLES",
	"  Display whole dts info:",
	"    %s> dts -a",
	"       {",
	"           model=<Qualcomm Technologies, Inc. Monaco WDP V1.1>;",
    "           compatible=<qcom,monaco>;",
    "           qcom,msm-id=< 0x1e6 0x10000 >;",
    "           qcom,board-id=< 0x10124 0x0 >;",
    "\n",
	"  Display whole dts info with address:",
	"    %s> dts -f",
	"       ffffff806f28a458:{",
	"           ffffff806f28a5b8:model=<Qualcomm Technologies, Inc. Monaco WDP V1.1>;",
    "           ffffff806f28a618:compatible=<qcom,monaco>;",
    "           ffffff806f28a678:qcom,msm-id=< 0x1e6 0x10000 >;",
    "           ffffff806f28a7f8:qcom,board-id=< 0x10124 0x0 >;",
    "\n",
	"  Display one node info by node name:",
	"    %s> dts -n memory",
	"       memory{",
	"           ddr_device_type=< 0x7 >;",
    "           device_type=<memory>;",
    "           reg=< 0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000 >;",
    "       };",
    "\n",
	"  Display one node info by node full path:",
	"    %s> dts -p /memory",
	"       memory{",
	"           ddr_device_type=< 0x7 >;",
    "           device_type=<memory>;",
    "           reg=< 0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000 >;",
    "       };",
    "\n",
	"  Display physic memory total size:",
	"    %s> dts -s",
	"       =========================================",
	"         0x40000000~0x7ee00000  size:0x3ee00000 ",
    "         0x80000000~0xc0000000  size:0x40000000 ",
	"       =========================================",
    "          Total size:    2030M ",
    "\n",
	"  Read out the whole dtb memory:",
	"    %s> dts -b ./dts.dtb",
	"       save dtb to ./dts.dtb",
    "\n",
    "       please use below command to generate dts file:",
    "           dtc -I dtb -O dts -o ./xx.dts ./dts.dtb",
    "\n",
    NULL
};

static struct command_table_entry command_table[] = {
    { "dts", cmd_dts, help_dts, 0 },
    { NULL }
};

struct dts_offset_table {
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
} dts_offset_table;

static void offset_table_init(void) {
	BZERO(&dts_offset_table, sizeof(dts_offset_table));
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
}

/**define all the struct which need calc struct size */
static struct dts_size_table {
    long device_node;
    long property;

    // DEFINE_MEMBER(vm_struct,size)
} dts_size_table;

static void size_table_init(void) {
	BZERO(&dts_size_table, sizeof(dts_size_table));
    struct_size_init(device_node);
    struct_size_init(property);

    // field_size_init(vm_struct, size); 
}

void __attribute__((constructor)) dts_init(void) {
    register_extension(command_table);
    offset_table_init();
    size_table_init();
}

void __attribute__((destructor)) dts_fini(void) {
    // fprintf(fp, "dts_fini\n");
}

void cmd_dts(void)
{
    int c;
    int flags;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "safb:n:p:")) != EOF) {
		switch(c) {
            case 'a': //print dts info
                flags |= DTS_ALL;
                dts_parser_device_tree_node(flags);
                break;
            case 'f': //print dts info with address
                flags |= DTS_ADDR;
                dts_parser_device_tree_node(flags);
                break;
            case 'b': //store dts info to devicetree.dtb
                dts_read_dtb(optarg);
                break;
            case 'n': //print a specified node info by name
                flags |= DTS_ALL;
                dts_parser_node_info(optarg,flags);
                break;
            case 'p': //print a specified node info by path
                flags |= DTS_PATH;
                dts_parser_node_info(optarg,flags);
                break;
            case 's': //print memory size
                dts_get_ddr_size();
                break;
            default:
                argerrs++;
                break;
		}
	}
    if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);
}

bool dts_has_prop_name(ulong addr,char *name){
    while (addr)
    {
        void *prop_buf = dts_read_struct(addr,struct_size(property),"property");
        if(prop_buf == NULL) return false;
        ulong name_addr = ULONG(prop_buf + field_offset(property,name));
        // read name
        char prop_name[64];
        dts_read_cstring(name_addr,prop_name,64, "property_name");
        if (!strcmp(prop_name, name)) {
            FREEBUF(prop_buf);
            return true;
        }
        addr = ULONG(prop_buf + field_offset(property,next));
        FREEBUF(prop_buf);
    }
    return false;
}

int dts_get_prop_value(ulong addr,char *name, ulong* data){
    int length = 0;
    while (addr)
    {
        void *prop_buf = dts_read_struct(addr,struct_size(property),"property");
        if(prop_buf == NULL) return 0;
        ulong name_addr = ULONG(prop_buf + field_offset(property,name));
        // read name
        char prop_name[64];
        dts_read_cstring(name_addr,prop_name,64, "property_name");
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

int dts_get_ddr_size(){
    if (!symbol_exists("of_root")){
        error(FATAL, "of_root doesn't exist in this kernel!\n");
        return 0;
    }
    ulong node = dts_find_node_by_path("/memory");
    if (node == 0)
        return 0;
    void *node_buf = dts_read_struct(node,struct_size(device_node),"device_node");
    if(node_buf == NULL) return 0;
    ulong properties = ULONG(node_buf + field_offset(device_node,properties));
    FREEBUF(node_buf);
    if (properties == 0)
        return 0;
    ulong val_addr = 0;
    bool has_mem_node = dts_has_prop_name(properties,"device_type");
    // read property of device_type
    int len = dts_get_prop_value(properties,"device_type", &val_addr);
    void *prop_val = dts_read_struct(val_addr,len,"property_value");
    if (!has_mem_node || strcmp(prop_val, "memory")){
        return 0;
    }
    // read property of reg
    //       <|  start     | |   size     |
    // reg = <0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000>
    len = dts_get_prop_value(properties,"reg", &val_addr);
    prop_val = dts_read_struct(val_addr,len,"property_value");
    int count = len / 4;
    long long unsigned regs[count];
    for (int i = 0; i < count; ++i) {
        regs[i] = dts_bigToLittleEndian(UINT(prop_val + i * sizeof(int)));
    }
    int group_cnt = count / 4;
    ulong total_size = 0;
    char size_buf[BUFSIZE];
    fprintf(fp, "=========================================\n");
    for (int i = 0; i < group_cnt; ++i) {
        long long unsigned addr = (regs[i * 4 + 0] << 32) | regs[i * 4 + 1];
        long long unsigned size = (regs[i * 4 + 2] << 32) | regs[i * 4 + 3];
        sprintf(size_buf, "0x%llx~0x%llx",addr,(addr + size));
        fprintf(fp, "  %s size:0x%llx\n",mkstring(size_buf, 30, LJUST,size_buf),size);
        total_size += size;
    }
    fprintf(fp, "=========================================\n");
    fprintf(fp, "Total size:%8ldM\n",total_size/1024/1024);
    return total_size;
}

ulong dts_find_node_by_name(char *name){
    ulong node = 0;
    ulong of_root_addr = symbol_value("of_root");
    if (!of_root_addr) return 0;
    ulong of_root = dts_read_pointer(of_root_addr,"of_root");
    for (node = dts_find_all_nodes(of_root,of_root); node; node = dts_find_all_nodes(node,of_root)){
        if (dts_node_name_eq(node, name)){
            return node;
        }
    } 
    return 0;
}

ulong dts_find_node_by_path(char *path){
	ulong np = 0;
    ulong of_root_addr = symbol_value("of_root");
    if (!of_root_addr) return 0;
    ulong of_root = dts_read_pointer(of_root_addr,"of_root");
	if (strcmp(path, "/") == 0)
		return of_root;
	if (!np)
		np = of_root;
	np = dts_find_node_by_full_path(np, path);
	return np;
}

ulong dts_find_node_by_full_path(ulong node,char *path){
	const char *separator = strchr(path, ':');
	while (node && *path == '/') {
		path++; /* Increment past '/' delimiter */
		node = dts_of_find_node_by_path(node, path);
		path = dts_strchrnul(path, '/');
		if (separator && separator < path)
			break;
	}
	return node;
}

ulong dts_of_find_node_by_path(ulong parent,const char *path){
	ulong child;
	int len;
	len = strcspn(path, "/:");
	if (!len)
		return 0;
	for (child = dts_of_get_next_child(parent, 0); child != 0; \
	     child = dts_of_get_next_child(parent, child)) {
        void *node_buf = dts_read_struct(child,struct_size(device_node),"device_node");
        if(node_buf == NULL) return false;
        ulong full_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
        // read full name
        char full_name[64];
        dts_read_cstring(full_name_addr,full_name,64, "device_node_full_name");
        FREEBUF(node_buf);
		const char *name = dts_kbasename(full_name);
		if (strncmp(path, name, len) == 0 && (strlen(name) == len))
			return child;
	}
	return 0;
}

ulong dts_of_get_next_child(ulong node,ulong prev){
	ulong next;
	if (!node)
		return 0;
    if (prev > 0){
        void *node_buf = dts_read_struct(prev,struct_size(device_node),"device_node");
        if(node_buf == NULL) return 0;
        ulong sibling = ULONG(node_buf + field_offset(device_node,sibling));
        FREEBUF(node_buf);
        next = sibling;
    }else{
        void *node_buf = dts_read_struct(node,struct_size(device_node),"device_node");
        if(node_buf == NULL) return 0;
        ulong child = ULONG(node_buf + field_offset(device_node,child));
        FREEBUF(node_buf);
        next = child;
    }
	return next;
}

void dts_parser_node_info(char *name,int flag){
    if (!symbol_exists("of_root")){
        error(FATAL, "of_root doesn't exist in this kernel!\n");
        return;
    }
    ulong node = 0;
    if (flag & DTS_PATH){
        node = dts_find_node_by_path(name);
    }else{
        node = dts_find_node_by_name(name);
    }
    if (node == 0)
        return;
    void *node_buf = dts_read_struct(node,struct_size(device_node),"device_node");
    if(node_buf == NULL) return;
    ulong full_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
    ulong properties = ULONG(node_buf + field_offset(device_node,properties));
    ulong child = ULONG(node_buf + field_offset(device_node,child));
    // read full name
    char full_name[64];
    dts_read_cstring(full_name_addr,full_name,64, "device_node_full_name");
    FREEBUF(node_buf);
    if (flag & DTS_ADDR){
        fprintf(fp, "%lx:%s{\n",node, full_name);
    }else{
        fprintf(fp, "%s{\n",full_name);
    }
    bool is_symbol_node = false;
    if (strstr(full_name, "symbols") != NULL){
        is_symbol_node = true;
    }
    if (properties > 0){
        dts_parser_properties(properties,0,is_symbol_node,flag);
    }
    if (child > 0){
        fprintf(fp, "\n");
        dts_parser_node(child,1,flag);
    }
    fprintf(fp, "};\n\n");
}

bool dts_node_name_eq(ulong np, const char *name){
	const char *node_name;
	size_t len;
	if (!np)
		return false;
    void *node_buf = dts_read_struct(np,struct_size(device_node),"device_node");
    if(node_buf == NULL) return false;
    ulong full_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
    // read full name
    char full_name[64];
    dts_read_cstring(full_name_addr,full_name,64, "device_node_full_name");
    FREEBUF(node_buf);

	node_name = dts_kbasename(full_name);
	len = dts_strchrnul(node_name, '@') - node_name;
	return (strlen(name) == len) && (strncmp(node_name, name, len) == 0);
}

char *dts_strchrnul(const char *s, int c){
	while (*s && *s != (char)c)
		s++;
	return (char *)s;
}

const char *dts_kbasename(const char *path){
	const char *tail = strrchr(path, '/');
	return tail ? tail + 1 : path;
}

ulong dts_find_all_nodes(ulong prev,ulong root){
	ulong parent,child,sibling;
    ulong np = 0;
    void *node_buf = dts_read_struct(prev,struct_size(device_node),"device_node");
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
        void *node_buf = dts_read_struct(np,struct_size(device_node),"device_node");
        if(node_buf == NULL) return np;
        parent = ULONG(node_buf + field_offset(device_node,parent));
        sibling = ULONG(node_buf + field_offset(device_node,sibling));
        FREEBUF(node_buf);
		while (parent && !sibling){
            np = parent;
            void *node_buf = dts_read_struct(np,struct_size(device_node),"device_node");
            if(node_buf == NULL) return np;
            parent = ULONG(node_buf + field_offset(device_node,parent));
            sibling = ULONG(node_buf + field_offset(device_node,sibling));
            FREEBUF(node_buf);
        }
		np = sibling; /* Might be null at the end of the tree */
	}
	return np;
}

void dts_read_dtb(char *path){
    if (!symbol_exists("initial_boot_params")){
        error(FATAL, "initial_boot_params doesn't exist in this kernel!\n");
        return;
    }
    ulong initial_boot_params_addr = symbol_value("initial_boot_params");
    if (!initial_boot_params_addr) return;
    ulong initial_boot_params = dts_read_pointer(initial_boot_params_addr,"initial_boot_params");
    fprintf(fp, "initial_boot_params:%lx\n",initial_boot_params);
    void *header = dts_read_struct(initial_boot_params,20,"dtb header");
    if(header == NULL) return;
    int magic = UINT(header);
    if (magic != 0xEDFE0DD0){
        fprintf(fp, "magic:%x is not correct !\n",magic);
        FREEBUF(header);
        return;
    }
    ulong db_size = ULONG(header + 4);
    db_size=((db_size & 0xFF)<<24)|((db_size & 0xFF00)<<8)|((db_size & 0xFF0000)>>8)|((db_size & 0xFF000000)>>24);
    if(db_size > DTB_MAX_SIZE) {
        fprintf(fp, "too large dtb size %ld\n",db_size);
        FREEBUF(header);
        return;
    }
    // fprintf(fp, "magic:%x\n",magic);
    // fprintf(fp, "db_size:%ld\n",db_size);
    FREEBUF(header);
    // mkstemp(DTB_default);
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        fprintf(fp, "Failed to open file");
        return;
    }
    void *dtb_buf = dts_read_struct(initial_boot_params,db_size,"read dtb");
    fwrite(dtb_buf, db_size, 1, file);
    // size_t written = fwrite(dtb_buf, db_size, 1, file);
    // if (written != db_size) {
    //     fprintf(fp, "Failed to write to file");
    //     fclose(file);
    //     FREEBUF(dtb_buf);
    //     return;
    // }
    fprintf(fp, "save dtb to %s",path);
    fclose(file);
    FREEBUF(dtb_buf);
}

void dts_parser_device_tree_node(int flag){
    if (!symbol_exists("of_root")){
        error(FATAL, "of_root doesn't exist in this kernel!\n");
        return;
    }
    ulong of_root_addr = symbol_value("of_root");
    if (!of_root_addr) return;
    ulong of_root = dts_read_pointer(of_root_addr,"of_root");
    dts_parser_node(of_root,0,flag);
}

void dts_parser_node(ulong node_addr,int level,int flag){
    void *node_buf = dts_read_struct(node_addr,struct_size(device_node),"device_node");
    if(node_buf == NULL) return;
    ulong full_name_addr = ULONG(node_buf + field_offset(device_node,full_name));
    ulong properties = ULONG(node_buf + field_offset(device_node,properties));
    ulong child = ULONG(node_buf + field_offset(device_node,child));
    ulong sibling = ULONG(node_buf + field_offset(device_node,sibling));
    // read full name
    char full_name[64];
    dts_read_cstring(full_name_addr,full_name,64, "device_node_full_name");
    FREEBUF(node_buf);
    for (int i = 0; i < level; i++) {
        fprintf(fp, "\t");
    }
    if (flag & DTS_ADDR){
        fprintf(fp, "%lx:%s{\n",node_addr, full_name);
    }else{
        fprintf(fp, "%s{\n",full_name);
    }
    bool is_symbol_node = false;
    if (strstr(full_name, "symbols") != NULL){
        is_symbol_node = true;
    }
    if (properties > 0){
        dts_parser_properties(properties,level,is_symbol_node,flag);
    }
    int sibl_level = level;
    int chil_level = level;
    if (child > 0){
        fprintf(fp, "\n");
        chil_level += 1;
        dts_parser_node(child,chil_level,flag);
    }
    for (int i = 0; i < level; i++) {
        fprintf(fp, "\t");
    }
    fprintf(fp, "};\n\n");
    if (sibling > 0){
        dts_parser_node(sibling,sibl_level,flag);
    }
}

const char* prop_strings[] = {
    "model",
    "compatible",
    "bootargs",
    "name",
    "function",
    "label",
    "fsmgr_flags",
    "pins",
    "parts",
    "serial",
    "hsuart",
    "names",
};

const char* prop_integer[] = {
    "phandle",
    "reg",
    "size",
    "cells",
    "addr",
    "offset",
    "id",
    "strength",
};

bool dts_is_prop_strings(char* name){
    int count = sizeof(prop_strings)/sizeof(prop_strings[0]);
    for (int i = 0; i < count; ++i) {
        // size_t prefixLength = strlen(prop_strings[i]);
        // if (!strncmp(name, prop_strings[i], prefixLength)) {
        //     return true;
        // }
        if (strstr(name, prop_strings[i]) != NULL){
            return true;
        }
    }
    return false;
}

bool dts_is_prop_int(char* name){
    int count = sizeof(prop_integer)/sizeof(prop_integer[0]);
    for (int i = 0; i < count; ++i) {
        if (!strcmp(prop_integer[i], name)) {
            return true;
        }
    }
    return false;
}

unsigned int dts_bigToLittleEndian(unsigned int num) {
    return ((num >> 24) & 0xFF) | ((num >> 8) & 0xFF00) | ((num << 8) & 0xFF0000) | ((num << 24) & 0xFF000000);
}

void dts_parser_properties(ulong propertie_addr,int level,bool is_symbol,int flag){
    ulong addr = propertie_addr;
    int prop_level = level + 1;
    while (addr)
    {
        void *prop_buf = dts_read_struct(addr,struct_size(property),"property");
        if(prop_buf == NULL) return;
        ulong name_addr = ULONG(prop_buf + field_offset(property,name));
        // read name
        char prop_name[64];
        dts_read_cstring(name_addr,prop_name,64, "property_name");
        if (!strcmp(prop_name, "name")) {
            addr = ULONG(prop_buf + field_offset(property,next));
            FREEBUF(prop_buf);
            continue;
        }
        int length = UINT(prop_buf + field_offset(property,length));
        ulong value_addr = ULONG(prop_buf + field_offset(property,value));
        for (int i = 0; i < prop_level; i++) {
            fprintf(fp, "\t");
        }
        if (length == 0){
            if (flag & DTS_ADDR){
                fprintf(fp, "%lx:%s;\n",addr,prop_name);
            }else{
                fprintf(fp, "%s;\n",prop_name);
            }
        }else{
            void *prop_val = dts_read_struct(value_addr,length,"property_value");
            if (is_symbol || dts_is_prop_strings(prop_name)){
                if (flag & DTS_ADDR){
                    fprintf(fp, "%lx:%s=<%s>;\n",addr,prop_name,(char*)prop_val);
                }else{
                    fprintf(fp, "%s=<%s>;\n",prop_name,(char*)prop_val);
                }
            }else if (dts_is_prop_int(prop_name) || ((length % 4) == 0)){
                if (flag & DTS_ADDR){
                    fprintf(fp, "%lx:%s=< ",addr,prop_name);
                }else{
                    fprintf(fp, "%s=< ",prop_name);
                }
                for (int i = 0; i < (length / 4); ++i) {
                    int val = UINT(prop_val + i * sizeof(int));
                    fprintf(fp, "0x%x ",dts_bigToLittleEndian(val));
                }
                fprintf(fp, ">;\n");
            }else{
                if (flag & DTS_ADDR){
                    fprintf(fp, "%lx:%s=<%s>;\n",addr,prop_name,(char*)prop_val);
                }else{
                    fprintf(fp, "%s=<%s>;\n",prop_name,(char*)prop_val);
                }
            }
            FREEBUF(prop_val);
        }
        addr = ULONG(prop_buf + field_offset(property,next));
        FREEBUF(prop_buf);
    }
}

void* dts_read_struct(ulong kvaddr,int size, char* name){
    void* buf = (void *)GETBUF(size);
    if (!readmem(kvaddr, KVADDR, buf, size, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name,kvaddr);
        return NULL;
	}
    return buf;
}

ulong dts_read_pointer(ulong kvaddr,char* name){
    ulong val;
    if (!readmem(kvaddr, KVADDR, &val, sizeof(void *), name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, kvaddr);
        return -1;
	}
    return val;
}

void* dts_read_structure_field(ulong kvaddr,int offset, int size, char* name){
    ulong addr = kvaddr + offset;
    void *buf = (void *)GETBUF(size);
    if (!readmem(addr, KVADDR, buf, size, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, addr);
        return NULL;
	}
    return buf;
}

void dts_read_cstring(ulong kvaddr,char* buf, int len, char* name){
    if (!readmem(kvaddr, KVADDR, buf, len, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, kvaddr);
	}
}

int dts_for_each_hlist_entry(ulong hlist_head,int offset,ulong **ptr){
    ulong first = dts_read_pointer(hlist_head,"hlist_head");
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

int dts_for_each_list_entry(ulong list_head,int offset,ulong **ptr){
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    readmem(list_head, KVADDR, &ld.start,sizeof(ulong), "for_each_list_entry list_head", FAULT_ON_ERROR);
    ld.end = list_head;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return 0;
    int cnt = do_list(&ld);
    if(cnt==0)return 0;
    *ptr = ld.list_ptr;
    return cnt;
}

int dts_for_each_rbtree_entry(ulong rb_root,int offset,ulong **ptr){
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
