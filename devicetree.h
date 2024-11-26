// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef DTS_H_
#define DTS_H_

#include <linux/types.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "defs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define field_offset_init(type, field_name)             (dts_offset_table.type##_##field_name = MEMBER_OFFSET(#type, #field_name))
#define valid_field(field_name)	                        (dts_offset_table.field_name >= 0)
#define invalid_field(field_name)	                    (dts_offset_table.field_name == INVALID_OFFSET)
#define field_offset(type,field_name)		            (OFFSET_verify(dts_offset_table.type##_##field_name, (char *)__FUNCTION__, __FILE__, __LINE__, #field_name))

#define field_size_init(type, field_name)               (dts_size_table.type##_##field_name = MEMBER_SIZE(#type, #field_name))
#define field_size(type,field_name)		                (SIZE_verify(dts_size_table.type##_##field_name, (char *)__FUNCTION__, __FILE__, __LINE__, #field_name))
#define struct_size_init(type)                          (dts_size_table.type = STRUCT_SIZE(#type))
#define struct_size(type)		                        (SIZE_verify(dts_size_table.type, (char *)__FUNCTION__, __FILE__, __LINE__, #type))
#define valid_struct(type)	                            (dts_size_table.type >= 0)
#define INVALID_VALUE		                            (-1)

#define DEFINE_MEMBER(type, field_name)  long type##_##field_name;

#define DTS_ALL		(0x0001)
#define DTS_ADDR	(0x0002)
#define DTS_PATH	(0x0004)

#define DTB_MAX_SIZE 0x100000

int dts_get_prop_value(ulong addr,char *name, ulong* data);
int dts_get_ddr_size();
bool dts_has_prop_name(ulong addr,char *name);
char *dts_strchrnul(const char *s, int c);
const char *dts_kbasename(const char *path);
ulong dts_find_all_nodes(ulong prev,ulong root);
void dts_parser_node_info(char *name,int flag);
ulong dts_find_node_by_name(char *name);
ulong dts_find_node_by_path(char *path);
ulong dts_find_node_by_full_path(ulong node,char *path);
ulong dts_of_find_node_by_path(ulong parent,const char *path);
ulong dts_of_get_next_child(ulong node,ulong prev);
bool dts_node_name_eq(ulong np, const char *name);
void dts_read_dtb(char *path);
void dts_parser_device_tree_node(int flag);
void dts_parser_node(ulong node_addr,int level,int flag);
void dts_parser_properties(ulong propertie_addr,int level,bool is_symbol,int flag);
bool dts_is_prop_strings(char* name);
bool dts_is_prop_int(char* name);
unsigned int dts_bigToLittleEndian(unsigned int num);

void* dts_read_struct(ulong kvaddr,int size, char* name);
ulong dts_read_pointer(ulong kvaddr,char* name);
void* dts_read_structure_field(ulong kvaddr,int offset, int size, char* name);
void dts_read_cstring(ulong kvaddr,char* buf, int len, char* name);

int dts_for_each_hlist_entry(ulong hlist_head,int offset,ulong **ptr);
int dts_for_each_list_entry(ulong list_head,int offset,ulong **ptr);
int dts_for_each_rbtree_entry(ulong rb_root,int offset,ulong **ptr);


#endif //  DTS_H_