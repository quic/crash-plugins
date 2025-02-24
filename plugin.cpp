// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "plugin.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

PaserPlugin::PaserPlugin(){
    // std::cout << "PaserPlugin" << std::endl;
    field_init(task_struct, active_mm);
    field_init(task_struct, mm);
    field_init(task_struct, tasks);
    struct_init(task_struct);

    field_init(mm_struct, pgd);
    field_init(mm_struct, arg_start);
    field_init(mm_struct, arg_end);
    if (THIS_KERNEL_VERSION < LINUX(6,1,0)){
        field_init(mm_struct, mmap);
    }else{
        field_init(mm_struct, mm_mt);
    }
    struct_init(mm_struct);

    field_init(maple_tree,ma_root);

    field_init(vm_area_struct,vm_start);
    field_init(vm_area_struct,vm_end);
    field_init(vm_area_struct,vm_flags);
    field_init(vm_area_struct, vm_next);
    struct_init(vm_area_struct);

    field_init(page, _mapcount);
    field_init(page, freelist);
    field_init(page, units);
    field_init(page, index);
    field_init(page, private);
    struct_init(page);

    field_init(list_head, prev);
    field_init(list_head, next);
    struct_init(list_head);
    //print_table();
}

bool PaserPlugin::isNumber(const std::string& str) {
    regex_t decimal, hex;
    bool result = false;
    if (regcomp(&decimal, "^-?\\d+$", REG_EXTENDED)) {
        fprintf(fp, "Could not compile decimal regex\n");
        return false;
    }
    if (regcomp(&hex, "^0[xX][0-9a-fA-F]+$", REG_EXTENDED)) {
        fprintf(fp, "Could not compile hex regex \n");
        regfree(&decimal);
        return false;
    }
    if (!regexec(&decimal, str.c_str(), 0, NULL, 0) || !regexec(&hex, str.c_str(), 0, NULL, 0)) {
        result = true;
    }
    regfree(&decimal);
    regfree(&hex);
    return result;
}

void PaserPlugin::convert_size(int64_t size,char* buf){
    if (size < 1024){
        sprintf(buf, "%" PRId64 "b",size);
    }else if (size < 1024 * 1024){
        sprintf(buf, "%.2fKb",(float)size/1024);
    }else if (size < 1024 * 1024 * 1024){
        sprintf(buf, "%.2fMb",(float)size/1024/1024);
    }else{
        sprintf(buf, "%.2fGb",(float)size/1024/1024/1024);
    }
}

void PaserPlugin::initialize(void){
    cmd_help = new char*[help_str_list.size()+1];
    for (size_t i = 0; i < help_str_list.size(); ++i) {
        cmd_help[i] = TO_CONST_STRING(help_str_list[i].c_str());
    }
    cmd_help[help_str_list.size()] = nullptr;
}

void PaserPlugin::type_init(const std::string& type){
    std::string name = type;
    typetable[name] = std::make_unique<Typeinfo>(type);
}

void PaserPlugin::type_init(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    typetable[name] = std::make_unique<Typeinfo>(type,field);
}

int PaserPlugin::type_offset(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->offset();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

int PaserPlugin::type_size(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->size();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

int PaserPlugin::type_size(const std::string& type){
    std::string name = type;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->size();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

void PaserPlugin::print_backtrace(){
    void *buffer[100];
    int nptrs = backtrace(buffer, 100);
    char **strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        fprintf(fp, "backtrace_symbols");
    }
    for (int i = 0; i < nptrs; i++) {
        fprintf(fp, "%s\n", strings[i]);
    }
    free(strings);
}

void PaserPlugin::print_table(){
    char buf[BUFSIZE];
    for (const auto& pair : typetable) {
        sprintf(buf, "%s", pair.first.c_str());
        fprintf(fp, "%s",mkstring(buf, 45, LJUST, buf));
        sprintf(buf, ": offset:%d", pair.second.get()->m_offset);
        fprintf(fp, "%s",mkstring(buf, 15, LJUST, buf));
        fprintf(fp, " size:%d\n",pair.second.get()->m_size);
    }
}

std::vector<ulong> PaserPlugin::for_each_radix(ulong root_rnode){
    std::vector<ulong> res;
    size_t entry_num = do_radix_tree(root_rnode, RADIX_TREE_COUNT, NULL);
    struct list_pair *entry_list = (struct list_pair *)GETBUF((entry_num + 1) * sizeof(struct list_pair));
    entry_list[0].index = entry_num;
    do_radix_tree(root_rnode, RADIX_TREE_GATHER, entry_list);
    for (size_t i = 0; i < entry_num; ++i){
        ulong addr = (ulong)entry_list[i].value;
        if (!is_kvaddr(addr))continue;
        res.push_back(addr);
    }
    return res;
}

std::vector<ulong> PaserPlugin::for_each_mptree(ulong maptree_addr){
    std::vector<ulong> res;
    size_t entry_num = do_maple_tree(maptree_addr, MAPLE_TREE_COUNT, NULL);
    struct list_pair *entry_list = (struct list_pair *)GETBUF(entry_num * sizeof(struct list_pair));
    do_maple_tree(maptree_addr, MAPLE_TREE_GATHER, entry_list);
    for (size_t i = 0; i < entry_num; ++i){
        ulong addr = (ulong)entry_list[i].value;
        if (!is_kvaddr(addr))continue;
        res.push_back(addr);
    }
    return res;
}

std::vector<ulong> PaserPlugin::for_each_xarray(ulong xarray_addr){
    std::vector<ulong> res;
    size_t entry_num = do_xarray(xarray_addr, XARRAY_COUNT, NULL);
    struct list_pair *entry_list = (struct list_pair *)GETBUF((entry_num + 1) * sizeof(struct list_pair));
    entry_list[0].index = entry_num;
    do_xarray(xarray_addr, XARRAY_GATHER, entry_list);
    for (size_t i = 0; i < entry_num; ++i){
        ulong addr = (ulong)entry_list[i].value;
        if (!is_kvaddr(addr))continue;
        res.push_back(addr);
    }
    return res;
}

std::vector<ulong> PaserPlugin::for_each_rbtree(ulong rb_root,int offset){
    std::vector<ulong> res;
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
    if(cnt==0)return res;
    treeList = (ulong *)GETBUF(cnt * sizeof(void *));
    retrieve_list(treeList, cnt);
    for (int i = 0; i < cnt; ++i) {
        if (!is_kvaddr(treeList[i]))continue;
        // LOGI("node addr:%lx\n",treeList[i]);
        treeList[i] -= td.node_member_offset;
        res.push_back(treeList[i]);
    }
    FREEBUF(treeList);
    hq_close();
    return res;
}

std::vector<ulong> PaserPlugin::for_each_list(ulong list_head,int offset){
    std::vector<ulong> res;
    void *buf = read_struct(list_head,"list_head");
    if(buf == nullptr) return res;
    ulong next = ULONG(buf + field_offset(list_head,next));
    ulong prev = ULONG(buf + field_offset(list_head,prev));
    FREEBUF(buf);
    if (!next || (next == list_head)) {
        return res;
    }
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    readmem(list_head, KVADDR, &ld.start,sizeof(ulong), TO_CONST_STRING("for_each_list list_head"), FAULT_ON_ERROR);
    ld.end = list_head;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return res;
    int cnt = do_list(&ld);
    if(cnt==0)return res;
    for (int i = 0; i < cnt; ++i) {
        ulong node_addr = ld.list_ptr[i];
        if (!is_kvaddr(node_addr))continue;
        res.push_back(node_addr);
    }
    FREEBUF(ld.list_ptr);
    return res;
}

std::vector<ulong> PaserPlugin::for_each_hlist(ulong hlist_head,int offset){
    std::vector<ulong> res;
    ulong first = read_pointer(hlist_head,"hlist_head");
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    ld.start = first;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return res;
    int cnt = do_list(&ld);
    if(cnt==0)return res;
    for (int i = 0; i < cnt; ++i) {
        ulong node_addr = ld.list_ptr[i];
        if (!is_kvaddr(node_addr))continue;
        res.push_back(node_addr);
    }
    FREEBUF(ld.list_ptr);
    return res;
}

std::vector<ulong> PaserPlugin::for_each_process(){
    std::vector<ulong> res_list;
    ulong init_task = csymbol_value("init_task");
    int offset = field_offset(task_struct,tasks);
    ulong list_head_addr = init_task + offset;
    // fprintf(fp, "list_head_addr:%lx \n",list_head_addr);
    std::vector<ulong> task_list = for_each_list(list_head_addr,offset);
    for (const auto& task_addr : task_list) {
        if(task_addr == init_task)continue;
        ulong mm_struct = read_pointer(task_addr + field_offset(task_struct,mm), "task_struct_mm");
        if (mm_struct == 0)continue;
        if(!task_exists(task_addr))continue;
        if(std::find(res_list.begin(), res_list.end(), task_addr) != res_list.end())continue;
        res_list.push_back(task_addr);
    }
    return res_list;
}

std::vector<ulong> PaserPlugin::for_each_threads(){
    std::vector<ulong> task_list;
    struct task_context* tc = FIRST_CONTEXT();
    task_list.push_back(tc->task);
    for (size_t i = 0; i < RUNNING_TASKS(); i++, tc++){
        task_list.push_back(tc->task);
    }
    return task_list;
}

std::vector<ulong> PaserPlugin::for_each_vma(ulong& task_addr){
    std::vector<ulong> vma_list;
    ulong mm_addr = read_pointer(task_addr + field_offset(task_struct,mm), "task_struct_mm");
    if (!is_kvaddr(mm_addr))return vma_list;
    if (THIS_KERNEL_VERSION < LINUX(6,1,0)){
        ulong vma_addr = read_pointer(mm_addr + field_offset(mm_struct,mmap), "mm_struct_mmap");
        while (is_kvaddr(vma_addr)){
            vma_list.push_back(vma_addr);
            vma_addr = read_pointer(vma_addr + field_offset(vm_area_struct,vm_next), "vm_area_struct_next");
        }
    } else {
        ulong mm_mt_addr = mm_addr + field_offset(mm_struct,mm_mt);
        vma_list = for_each_mptree(mm_mt_addr);
    }
    return vma_list;
}

std::string PaserPlugin::read_start_args(ulong& task_addr){
    std::string result;
    if (!is_kvaddr(task_addr))return nullptr;
    ulong mm_addr = read_pointer(task_addr + field_offset(task_struct, mm), "task_struct_mm");
    void *buf = read_struct(mm_addr,"mm_struct");
    ulong arg_start = ULONG(buf + field_offset(mm_struct, arg_start));
    ulong arg_end = ULONG(buf + field_offset(mm_struct, arg_end));
    // ulong pgd = (ulong)VOID_PTR(buf + field_offset(mm_struct, pgd));
    // fprintf(fp, "pgd:%lx \n",pgd);
    FREEBUF(buf);
    ulong len = arg_end - arg_start;
    physaddr_t paddr_start;
    struct task_context *tc = task_to_context(task_addr);
    uvtop(tc, arg_start, &paddr_start, 0);
    // fprintf(fp, "pid :%ld arg_start %lx paddr_start %lx \n",tc->pid, arg_start, paddr_start);
    if(paddr_start == 0){
        return std::string(tc->comm);
    }

    buf = read_phys_memory(paddr_start, len, "read_args");
    char* args = static_cast<char*>(buf);
    //maybe swap
    if (args == nullptr || args[0] == '\0') {
        return std::string(tc->comm);
    }
    for (size_t i = 0; i < len; ++i) {
        if (args[i] != '\0') {
            result += args[i];
        }else{
            result += ' ';
        }
    }

    // remove all '\n'
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());

    // reslut = "     "
    if (result.find_first_not_of(' ') == std::string::npos) {
        result = std::string(tc->comm);
    } else {
        // result = "command    "
        size_t last_non_space = result.find_last_not_of(' ');
        if (last_non_space != std::string::npos) {
            result = result.substr(0, last_non_space + 1) + ' ';
        }
    }

    return result;
}

ulonglong PaserPlugin::read_structure_field(ulong kvaddr,const std::string& type,const std::string& field){
    int offset = type_offset(type,field);
    int size = type_size(type,field);
    std::string note = type + "_" + field;
    ulong addr = kvaddr + offset;
    ulonglong result = 0;
    void *buf = (void *)GETBUF(size);
    if (!readmem(addr, KVADDR, buf, size, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        FREEBUF(buf);
        return 0;
    }
    switch(size){
        case 1:
            result = UCHAR(buf);
            break;
        case 2:
            result = USHORT(buf);
            break;
        case 4:
            result = UINT(buf);
            break;
        case 8:
            result = ULONGLONG(buf);
            break;
        default:
            result = ULONG(buf);
    }
    FREEBUF(buf);
    return result;
}

std::string PaserPlugin::read_cstring(ulong kvaddr,int len, const std::string& note){
    char res[len];
    if (!readmem(kvaddr, KVADDR, res, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), kvaddr);
        return nullptr;
    }
    return std::string(res);
}

bool PaserPlugin::read_bool(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(bool),note);
    if(buf == nullptr){
        return false;
    }
    bool res = BOOL(buf);
    FREEBUF(buf);
    return res;
}

int PaserPlugin::read_int(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(int),note);
    if(buf == nullptr){
        return 0;
    }
    int res = INT(buf);
    FREEBUF(buf);
    return res;
}

uint PaserPlugin::read_uint(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(uint),note);
    if(buf == nullptr){
        return 0;
    }
    uint res = UINT(buf);
    FREEBUF(buf);
    return res;
}

long PaserPlugin::read_long(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(long),note);
    if(buf == nullptr){
        return 0;
    }
    long res = LONG(buf);
    FREEBUF(buf);
    return res;
}

ulong PaserPlugin::read_ulong(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(ulong),note);
    if(buf == nullptr){
        return 0;
    }
    ulong res = ULONG(buf);
    FREEBUF(buf);
    return res;
}

ulonglong PaserPlugin::read_ulonglong(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(ulonglong),note);
    if(buf == nullptr){
        return 0;
    }
    ulonglong res = ULONGLONG(buf);
    FREEBUF(buf);
    return res;
}

ushort PaserPlugin::read_ushort(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(ushort),note);
    if(buf == nullptr){
        return 0;
    }
    ushort res = USHORT(buf);
    FREEBUF(buf);
    return res;
}

short PaserPlugin::read_short(ulong kvaddr,const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(short),note);
    if(buf == nullptr){
        return 0;
    }
    short res = SHORT(buf);
    FREEBUF(buf);
    return res;
}

void* PaserPlugin::read_memory(ulong kvaddr,int len, const std::string& note){
    void* buf = (void *)GETBUF(len);
    if (!readmem(kvaddr, KVADDR, buf, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), kvaddr);
        FREEBUF(buf);
        return nullptr;
    }
    return buf;
}

void* PaserPlugin::read_phys_memory(ulong paddr, int len, const std::string& note){
    void* buf = (void *)GETBUF(len);
    if (!readmem(paddr, PHYSADDR, buf, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR)) {
        fprintf(fp, "Can't read %s at %lx\n", TO_CONST_STRING(note.c_str()), paddr);
        FREEBUF(buf);
        return NULL;
    }
    return buf;
}

void* PaserPlugin::read_struct(ulong kvaddr,const std::string& type){
    int size = type_size(type);
    void* buf = (void *)GETBUF(size);
    if (!readmem(kvaddr, KVADDR, buf, size, TO_CONST_STRING(type.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(type.c_str()),kvaddr);
        FREEBUF(buf);
        return nullptr;
    }
    return buf;
}

bool PaserPlugin::read_struct(ulong kvaddr,void* buf, int len, const std::string& note){
    if (!readmem(kvaddr, KVADDR, buf, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()),kvaddr);
        return false;
    }
    return true;
}

ulong PaserPlugin::read_pointer(ulong kvaddr, const std::string& note){
    void *buf = read_memory(kvaddr,sizeof(void *),note);
    if(buf == nullptr){
        return 0;
    }
    ulong res = (ulong)VOID_PTR(buf);
    FREEBUF(buf);
    return res;
}

unsigned char PaserPlugin::read_byte(ulong kvaddr, const std::string& note){
    unsigned char val;
    if (!readmem(kvaddr, KVADDR, &val, 1, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), kvaddr);
        return -1;
    }
    return val;
}

int PaserPlugin::csymbol_exists(const std::string& note){
    return symbol_exists(TO_CONST_STRING(note.c_str()));
}

ulong PaserPlugin::csymbol_value(const std::string& note){
    return symbol_value(TO_CONST_STRING(note.c_str()));
}

bool PaserPlugin::is_kvaddr(ulong addr){
    return IS_KVADDR(addr);
}

bool PaserPlugin::is_uvaddr(ulong addr, struct task_context* tc){
    return IS_UVADDR(addr,tc);
}

int PaserPlugin::page_to_nid(ulong page){
    int i;
    struct node_table *nt;
    physaddr_t paddr = page_to_phy(page);
    if (paddr == 0){
        return -1;
    }
    for (i = 0; i < vt->numnodes; i++){
        nt = &vt->node_table[i];
        physaddr_t end_paddr = nt->start_paddr + ((physaddr_t)nt->size * (physaddr_t)page_size);
        if ((paddr >= nt->start_paddr) && (paddr < end_paddr)){
            return i;
        }
    }
    return -1;
}

ulong PaserPlugin::virt_to_phy(ulong vaddr){
    return VTOP(vaddr);
}

ulong PaserPlugin::phy_to_virt(ulong paddr){
    return PTOV(paddr);
}

ulong PaserPlugin::phy_to_pfn(ulong paddr){
    return BTOP(paddr);
}

physaddr_t PaserPlugin::pfn_to_phy(ulong pfn){
    return PTOB(pfn);
}

ulong PaserPlugin::page_to_pfn(ulong page){
    return phy_to_pfn(page_to_phy(page));
}

ulong PaserPlugin::pfn_to_page(ulong pfn){
    return phy_to_page(pfn_to_phy(pfn));
}

ulong PaserPlugin::phy_to_page(ulong paddr){
    ulong page;
    if(phys_to_page(paddr, &page)){
        return page;
    }
    return 0;
}

physaddr_t PaserPlugin::page_to_phy(ulong page){
    physaddr_t paddr = 0;
    if (is_page_ptr(page, &paddr)){
        return paddr;
    }
    return 0;
}

std::string PaserPlugin::get_config_val(const std::string& conf_name){
    char *config_val;
    if (get_kernel_config(TO_CONST_STRING(conf_name.c_str()),&config_val) != IKCONFIG_N){
        std::string val(config_val);
        return val;
    }else{
        return "n";
    }
}

void PaserPlugin::cfill_pgd(ulonglong pgd, int type, ulong size){
    if (!IS_LAST_PGD_READ(pgd)) {
        readmem(pgd, type, machdep->pgd, size, TO_CONST_STRING("pgd page"), FAULT_ON_ERROR);
        machdep->last_pgd_read = (ulong)(pgd);
    }
}

void PaserPlugin::cfill_pmd(ulonglong pmd, int type, ulong size){
    if (!IS_LAST_PMD_READ(pmd)) {
        readmem(pmd, type, machdep->pmd, size, TO_CONST_STRING("pmd page"), FAULT_ON_ERROR);
        machdep->last_pmd_read = (ulong)(pmd);
    }
}

void PaserPlugin::cfill_ptbl(ulonglong ptbl, int type, ulong size){
    if (!IS_LAST_PTBL_READ(ptbl)) {
        readmem(ptbl, type, machdep->ptbl, size, TO_CONST_STRING("page table"), FAULT_ON_ERROR);
        machdep->last_ptbl_read = (ulong)(ptbl);
    }
}

// maybe we can refer to symbols.c is_binary_stripped
bool PaserPlugin::is_binary_stripped(std::string& filename){
    std::string command = "readelf -s " + filename;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        fprintf(fp, "Failed to run readelf command. \n");
        return false;
    }
    std::string output;
    char buffer[BUFSIZE];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    return output.find("Symbol table '.symtab' contains") == std::string::npos;
}

bool PaserPlugin::add_symbol_file(std::string& filename){
    if(is_binary_stripped(filename)){
        fprintf(fp, "This file is not symbols file \n");
        return false;
    }
    char buf[BUFSIZE];
    sprintf(buf, "add-symbol-file %s", filename.c_str());
    if(!gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR)){
        fprintf(fp, "add symbol file: %s failed\n", filename.c_str());
        return false;
    }
    return true;
}

void PaserPlugin::verify_userspace_symbol(std::string& symbol_name){
    char buf[BUFSIZE];
    sprintf(buf, "ptype %s", symbol_name.c_str());
    if(!gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR)){
        fprintf(fp, "verify_userspace_symbol: %s failed \n", symbol_name.c_str());
    }
}

std::string PaserPlugin::extract_string(const char *input) {
    std::string result;
    const char *ptr = input;
    while (*ptr != '\0') {
        if (!result.empty()) {
            result += ' ';
        }
        result += std::string(ptr);
        ptr += strlen(ptr) + 1;
    }
    return result;
}

int PaserPlugin::is_bigendian(void){
    int i = 0x12345678;
    if (*(char *)&i == 0x12)
        return TRUE;
    else
        return FALSE;
}

long PaserPlugin::read_enum_val(const std::string& enum_name){
     long enum_val = 0;
     enumerator_value(TO_CONST_STRING(enum_name.c_str()), &enum_val);
     return enum_val;
}

char PaserPlugin::get_printable(uint8_t d) {
    return std::isprint(d) ? static_cast<char>(d) : '.';
}

std::string PaserPlugin::print_line(uint64_t addr, const std::vector<uint8_t>& data) {
    std::vector<char> printable;
    std::vector<std::string> data_hex;
    for (uint8_t d : data) {
        printable.push_back(get_printable(d));
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", d);
        data_hex.push_back(hex);
    }
    while (printable.size() < 16) {
        printable.push_back(' ');
        data_hex.push_back("  ");
    }
    std::ostringstream oss;
    oss << std::setw(8) << std::setfill('0') << std::hex << addr << ": ";
    for (size_t i = 0; i < 16; ++i) {
        if (i % 2 == 0 && i > 0) {
            oss << " ";
        }
        oss << data_hex[i];
    }
    oss << " ";
    for (char c : printable) {
        oss << c;
    }
    oss << "\n";
    return oss.str();
}

std::string PaserPlugin::hexdump(uint64_t addr, const char* buf, size_t length, bool little_endian) {
    std::ostringstream sio;
    std::vector<uint8_t> data_list;
    if (little_endian) {
        data_list.assign(reinterpret_cast<const uint8_t*>(buf), reinterpret_cast<const uint8_t*>(buf) + length);
    } else {
        std::vector<size_t> places;
        for (size_t i = 0; i < length / 4; ++i) {
            places.push_back((i + 1) * 4 - 1);
            places.push_back((i + 1) * 4 - 2);
            places.push_back((i + 1) * 4 - 3);
            places.push_back(i * 4);
        }
        for (const auto& i : places) {
            data_list.push_back(static_cast<uint8_t>(buf[i]));
        }
    }
    uint64_t address = addr;
    std::vector<uint8_t> bb;
    size_t n = 0;
    for (uint8_t i : data_list) {
        bb.push_back(i);
        if (n == 15) {
            sio << print_line(address, bb);
            bb.clear();
            n = 0;
            address += 16;
        } else {
            ++n;
        }
    }
    if (!bb.empty()) {
        sio << print_line(address, bb);
    }
    return sio.str();
}
#pragma GCC diagnostic pop
