// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef MEMORY_H_
#define MEMORY_H_

#include <linux/types.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "defs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define field_offset_init(type, field_name)             (memory_offset_table.type##_##field_name = MEMBER_OFFSET(#type, #field_name))
#define valid_field(type, field_name)	                (memory_offset_table.type##_##field_name >= 0)
#define invalid_field(type, field_name)	                (memory_offset_table.type##_##field_name == INVALID_OFFSET)
#define field_offset(type,field_name)		            (OFFSET_verify(memory_offset_table.type##_##field_name, (char *)__FUNCTION__, __FILE__, __LINE__, #field_name))

#define field_size_init(type, field_name)               (memory_size_table.type##_##field_name = MEMBER_SIZE(#type, #field_name))
#define field_size(type,field_name)		                (SIZE_verify(memory_size_table.type##_##field_name, (char *)__FUNCTION__, __FILE__, __LINE__, #field_name))
#define struct_size_init(type)                          (memory_size_table.type = STRUCT_SIZE(#type))
#define struct_size(type)		                        (SIZE_verify(memory_size_table.type, (char *)__FUNCTION__, __FILE__, __LINE__, #type))
#define valid_struct(type)	                            (memory_size_table.type >= 0)
#define INVALID_VALUE		                            (-1)

#define DEFINE_MEMBER(type, field_name)  long type##_##field_name;

void* mm_read_struct(ulong kvaddr,int size, char* name);
ulong mm_read_pointer(ulong kvaddr,char* name);
void* mm_read_structure_field(ulong kvaddr,int offset, int size, char* name);
void mm_read_cstring(ulong kvaddr,char* buf, int len, char* name);

int mm_for_each_hlist_entry(ulong hlist_head,int offset,ulong **ptr);
int mm_for_each_list_entry(ulong list_head,int offset,ulong **ptr);
int mm_for_each_rbtree_entry(ulong rb_root,int offset,ulong **ptr);

void parser_vmap_area_list();

#define VM_IOREMAP	    (0x00000001)
#define VM_ALLOC	    (0x00000002)
#define VM_MAP		    (0x00000004)
#define VM_USERMAP	    (0x00000008)
#define VM_VPAGES	    (0x00000010)
#define VM_UNLIST	    (0x00000020)

#define PRINT_ALL	    (0x0001)
#define PRINT_PAGES	    (0x0002)

#define INITIAL_CAPACITY 5
typedef struct {
    ulong* data;
    int capacity;
    int count;
} AutoArray;

struct caller_module{
    char caller[BUFSIZE];
    int nr_pages;
};

enum memblock_flags {
	MEMBLOCK_NONE		= 0x0,	/* No special request */
	MEMBLOCK_HOTPLUG	= 0x1,	/* hotpluggable region */
	MEMBLOCK_MIRROR		= 0x2,	/* mirrored region */
	MEMBLOCK_NOMAP		= 0x4,	/* don't add to kernel direct mapping */
};

const char* memblock_flags_str[] = {  
    "MEMBLOCK_NONE",  
    "MEMBLOCK_HOTPLUG",  
    "MEMBLOCK_MIRROR",
	"",
    "MEMBLOCK_NOMAP",
};

struct sysinfo {
	ulong totalram;	/* Total usable main memory size */
	ulong freeram;	/* Available memory size */
	ulong sharedram;	/* Amount of shared memory */
	ulong bufferram;	/* Memory used by buffers */
	ulong totalswap;	/* Total swap space size */
	ulong swapcache;	/* Total swap space size */
	ulong filepages;	/* Total swap space size */
	ulong cached;	/* Total swap space size */
	ulong freeswap;	/* swap space still available */
	ulong totalhigh;	/* Total high memory size */
	ulong freehigh;	/* Available high memory size */
	ulong slab_rec;	/* Total swap space size */
	ulong slab_unrec;	/* Total swap space size */
	ulong kernelstack;	/* Total swap space size */
	ulong pagetable;	/* Total swap space size */
	ulong shmem;	/* Total swap space size */
};

#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
	LRU_UNEVICTABLE,
	NR_LRU_LISTS
};

struct vmap_area {
	unsigned long va_start;
	unsigned long va_end;

	struct rb_node rb_node;         /* address sorted rbtree */
	struct kernel_list_head list;          /* address sorted list */

	/*
	 * The following two variables can be packed, because
	 * a vmap_area object can be either:
	 *    1) in "free" tree (root is vmap_area_root)
	 *    2) or "busy" tree (root is free_vmap_area_root)
	 */
	union {
		unsigned long subtree_max_size; /* in "free" tree */
		void *vm;           /* in "busy" tree */
	};
};

AutoArray initArray();
void add_array_entry(AutoArray* arr, char* caller, int nr_page);
void freeArray(AutoArray* arr);

void parser_buddy_info();
void parser_cma_areas();
void parser_vmap_area_list();
void parser_reserved_mem();
void parser_mem_block();
void parser_memblock_type(ulong addr);
void parser_dma_buf();
void parser_dma_buf_attachment(ulong addr);
int get_cma_used_size(ulong bitmap_addr, ulong nr_pages,int order);
int count_ones_in_byte(ulong value);
void parser_memory_info();

int mm_get_prop_value(ulong addr,char *name, ulong* data);
bool mm_has_prop_name(ulong addr,char *name);
char *mm_strchrnul(char *s, int c);
char *mm_kbasename(char *path);
void mm_parser_node_info(char *name,int flag);
ulong mm_get_ddr_size();
ulong mm_find_all_nodes(ulong prev,ulong root);
ulong mm_find_node_by_path(char *path);
ulong mm_find_node_by_full_path(ulong node,char *path);
ulong mm_of_find_node_by_path(ulong parent,const char *path);
ulong mm_of_get_next_child(ulong node,ulong prev);
unsigned int mm_bigToLittleEndian(unsigned int num);
bool mm_node_name_eq(ulong np, char *name);
bool mm_node_fullname_eq(ulong np, char *name);
ulong mm_find_node_by_fullname(char *full_name);
ulong mm_find_node_by_name(char *name);
void get_reserved_mem(ulong* total_size,ulong* nomap_size,ulong* reusable_size);
ulong get_blockdev_pages(void);
void convert_size(ulong size,char* buf);
ulong get_vmalloc_size();
ulong get_cma_size();
void get_swap_cache(struct sysinfo* meminfo);
#endif //  MEMORY_H_