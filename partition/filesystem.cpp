// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "filesystem.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(FileSystem)
#endif

void Mount::cmd_main(void) {

}

void Mount::statfs(int width) {
    int64_t total_size = static_cast<int64_t>(f_bsize) * f_blocks;
    ulong used = f_bsize * (f_blocks - f_bfree);
    // ulong avail = f_bsize * f_bavail;
    ulong avail = total_size - used;
    double ratio = (double)used / (double)total_size;
    std::ostringstream oss;
    oss << std::left << std::setw(width) << dir_name << " "
        << std::left << std::setw(5) << fs_type << " "
        << std::left << std::setw(10) << f_blocks << " "
        << std::left << std::setw(10) << csize(f_bsize) << " "
        << std::left << std::setw(10) << csize(total_size) << " "
        << std::left << std::setw(10) << csize(used) << " "
        << std::left << std::setw(10) << csize(avail) << " "
        << std::fixed << std::setprecision(2) << ratio * 100 << "%";
    fprintf(fp, "%s \n",oss.str().c_str());
}

F2fs::F2fs(){
    field_init(f2fs_sb_info,blocksize);
    field_init(f2fs_sb_info,user_block_count);
    field_init(f2fs_sb_info,total_valid_block_count);
    field_init(f2fs_sb_info,current_reserved_blocks);
    field_init(f2fs_sb_info,mount_opt);
    field_init(f2fs_sb_info,raw_super);
    field_init(f2fs_mount_info,root_reserved_blocks);
    field_init(f2fs_super_block,block_count);
    field_init(f2fs_super_block,segment0_blkaddr);
    struct_init(f2fs_sb_info);
}

void F2fs::statfs(int width) {
    void *sbi = read_struct(fs_info_addr,"f2fs_sb_info");
    if(sbi == nullptr) return;
    f_bsize = UINT(sbi + field_offset(f2fs_sb_info,blocksize));
    uint32_t user_block_count = UINT(sbi + field_offset(f2fs_sb_info,user_block_count));
    uint32_t total_valid_block_count = UINT(sbi + field_offset(f2fs_sb_info,total_valid_block_count));
    uint32_t current_reserved_blocks = UINT(sbi + field_offset(f2fs_sb_info,current_reserved_blocks));
    f_bfree = user_block_count - total_valid_block_count - current_reserved_blocks;
    f_bavail = f_bfree - UINT(sbi + field_offset(f2fs_sb_info,mount_opt) + field_offset(f2fs_mount_info,root_reserved_blocks));
    ulong raw_super_addr = ULONG(sbi + field_offset(f2fs_sb_info,raw_super));
    ulong total_count = read_ulong(raw_super_addr + field_offset(f2fs_super_block,block_count),"f2fs_super_block block_count");
    uint start_count = read_uint(raw_super_addr + field_offset(f2fs_super_block,segment0_blkaddr),"f2fs_super_block segment0_blkaddr");
    f_blocks = total_count - start_count;
    FREEBUF(sbi);
    Mount::statfs(width);
}

Ext4::Ext4(){
    field_init(super_block,s_blocksize);
    field_init(ext4_sb_info,s_es);
    field_init(ext4_sb_info,s_overhead);
    field_init(ext4_sb_info,s_cluster_bits);
    field_init(ext4_sb_info,s_resv_clusters);
    field_init(ext4_sb_info,s_freeclusters_counter);
    field_init(ext4_sb_info,s_dirtyclusters_counter);
    field_init(ext4_super_block,s_blocks_count_hi);
    field_init(ext4_super_block,s_blocks_count_lo);
    field_init(ext4_super_block,s_r_blocks_count_hi);
    field_init(ext4_super_block,s_r_blocks_count_lo);
    field_init(percpu_counter,count);
    field_init(percpu_counter,counters);
    struct_init(ext4_sb_info);
    struct_init(ext4_super_block);
}

void Ext4::statfs(int width) {
    f_bsize = read_ulong(sb_addr + field_offset(super_block,s_blocksize),"super_block s_blocksize");
    void *sbi = read_struct(fs_info_addr,"ext4_sb_info");
    if(sbi == nullptr) return;
    ulong esb_addr = ULONG(sbi + field_offset(ext4_sb_info,s_es));
    void *esb = read_struct(esb_addr,"ext4_super_block");
    if(esb == nullptr) return;
    ulong s_resv_clusters = ULONG(sbi + field_offset(ext4_sb_info,s_resv_clusters));
    uint s_cluster_bits = UINT(sbi + field_offset(ext4_sb_info,s_cluster_bits));
    ulong s_overhead = ULONG(sbi + field_offset(ext4_sb_info,s_overhead));
    uint32_t s_blocks_count_hi = UINT(esb + field_offset(ext4_super_block,s_blocks_count_hi));
    uint32_t s_blocks_count_lo = UINT(esb + field_offset(ext4_super_block,s_blocks_count_lo));
    uint64_t ext4_blocks_count = (static_cast<uint64_t>(s_blocks_count_hi) << 32) | s_blocks_count_lo;
    uint32_t s_r_blocks_count_hi = UINT(esb + field_offset(ext4_super_block,s_r_blocks_count_hi));
    uint32_t s_r_blocks_count_lo = UINT(esb + field_offset(ext4_super_block,s_r_blocks_count_lo));
    uint64_t ext4_r_blocks_count = (static_cast<uint64_t>(s_r_blocks_count_hi) << 32) | s_r_blocks_count_lo;
    f_blocks = ext4_blocks_count - (s_overhead << s_cluster_bits);
    long long s_freeclusters_counter = percpu_counter_sum(fs_info_addr + field_offset(ext4_sb_info,s_freeclusters_counter));
    long long s_dirtyclusters_counter = percpu_counter_sum(fs_info_addr + field_offset(ext4_sb_info,s_dirtyclusters_counter));
    f_bfree = (s_freeclusters_counter - s_dirtyclusters_counter) << s_cluster_bits;
    long long resv_blocks = s_resv_clusters << s_cluster_bits;
    if (f_bfree < (ext4_r_blocks_count + resv_blocks)){
        f_bavail = 0;
    }else{
        f_bavail = f_bfree - (ext4_r_blocks_count + resv_blocks);
    }
    FREEBUF(sbi);
    FREEBUF(esb);
    Mount::statfs(width);
}

long long Ext4::percpu_counter_sum(ulong addr) {
    long long count = read_ulonglong(addr + field_offset(percpu_counter,count),"percpu_counter count");
    ulong counters = read_ulong(addr + field_offset(percpu_counter,counters),"percpu_counter counters");
    for (size_t i = 0; i < NR_CPUS; i++) {
        if (!kt->__per_cpu_offset[i])
            continue;
        ulong per_cpu_counter_addr = counters + kt->__per_cpu_offset[i];
        if (!is_kvaddr(per_cpu_counter_addr)) continue;
        count += read_int(per_cpu_counter_addr,"per_cpu_counter");
    }
    return count;
}

void FileSystem::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if(mount_list.size() == 0){
        parser_mount_tree();
    }
    while ((c = getopt(argcnt, args, "ts")) != EOF) {
        switch(c) {
            case 't':
                print_mount_tree(mount_list,0);
                break;
            case 's':
                print_partition_size();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

FileSystem::FileSystem(){
    field_init(nsproxy,mnt_ns);
    field_init(mnt_namespace,root);
    field_init(mnt_namespace,list);
    field_init(mount,mnt_devname);
    field_init(mount,mnt_child);
    field_init(mount,mnt_mounts);
    field_init(mount,mnt_mountpoint);
    field_init(mount,mnt);
    field_init(mount,mnt_list);
    field_init(vfsmount,mnt_sb);
    field_init(vfsmount,mnt_flags);
    field_init(super_block,s_type);
    field_init(super_block,s_fs_info);
    field_init(file_system_type,name);
    struct_init(mount);
    cmd_name = "df";
    help_str_list={
        "df",                /* command name */
        "dump filesystem information",    /* short description */
        "-t \n"
            "  df -s\n"
            "  This command dumps the mount info.",
        "\n",
        "EXAMPLES",
        "  Display mount info by tree hierarchy:",
        "    %s> df -t",
        "    [rootfs]rootfs --> /",
        "        [ext4]/dev/block/dm-4 --> /",
        "            [tmpfs]tmpfs --> /dev",
        "                [devpts]devpts --> /dev/pts",
        "\n",
        "  Display partition size info:",
        "    %s> df -s",
        "    Partition                 Type  Blocks     Block SZ   Size       Used       Avail      Use%",
        "    /                         ext4  124545     4.00Kb     486.50Mb   485.01Mb   0b         99.69%",
        "    /metadata                 ext4  2940       4.00Kb     11.48Mb    160.00Kb   10.86Mb    1.36%",
        "    /product                  ext4  32258      4.00Kb     126.01Mb   125.61Mb   0b         99.68%",
        "    /system_ext               ext4  31968      4.00Kb     124.88Mb   124.48Mb   0b         99.68%",
        "    data                      f2fs  1834496    4.00Kb     7.00Gb     468.12Mb   2.53Gb     6.53%",
        "    /vendor                   ext4  83917      4.00Kb     327.80Mb   326.80Mb   0b         99.70%",
        "\n",
    };
    initialize();
}

void FileSystem::print_partition_size(){
    size_t max_len = 0;
    for (const auto& pair : sb_list) {
        std::shared_ptr<Mount> mnt_ptr = pair.second;
        max_len = std::max(max_len,mnt_ptr->dir_name.size());
    }
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(max_len) << "Partition" << " "
        << std::left << std::setw(5) << "Type" << " "
        << std::left << std::setw(10) << "Blocks" << " "
        << std::left << std::setw(10) << "Block SZ" << " "
        << std::left << std::setw(10) << "Size" << " "
        << std::left << std::setw(10) << "Used" << " "
        << std::left << std::setw(10) << "Avail" << " "
        << std::left << "Use%";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& pair : sb_list) {
        std::shared_ptr<Mount> mnt_ptr = pair.second;
        if (mnt_ptr->fs_type == "f2fs"){
            std::shared_ptr<F2fs> f2fs_ptr = std::dynamic_pointer_cast<F2fs>(mnt_ptr);
            f2fs_ptr->statfs(max_len);
        }else if (mnt_ptr->fs_type == "ext4"){
            std::shared_ptr<Ext4> ext4_ptr = std::dynamic_pointer_cast<Ext4>(mnt_ptr);
            ext4_ptr->statfs(max_len);
        }
    }
}

void FileSystem::print_mount_tree(std::vector<std::shared_ptr<Mount>>& mnt_list,int level){
    for (const auto& mnt_ptr : mnt_list) {
        for (int i = 0; i < level; i++) {
            fprintf(fp, "\t");
        }
        fprintf(fp, "[%s]%s --> %s\n",mnt_ptr->fs_type.c_str(),mnt_ptr->dev_name.c_str(),mnt_ptr->dir_name.c_str());
        if(mnt_ptr->childs.size() > 0){
            print_mount_tree(mnt_ptr->childs,(level + 1));
        }
    }
}

void FileSystem::parser_mount_tree(){
    if (!csymbol_exists("init_nsproxy")){
        fprintf(fp, "init_nsproxy doesn't exist in this kernel!\n");
        return;
    }
    ulong init_nsproxy_addr = csymbol_value("init_nsproxy");
    if (!is_kvaddr(init_nsproxy_addr)) return;
    ulong mnt_namespace_addr = read_pointer(init_nsproxy_addr + field_offset(nsproxy,mnt_ns),"nsproxy mnt_ns");
    if (!is_kvaddr(mnt_namespace_addr)) return;
    ulong root_mount_addr = read_pointer(mnt_namespace_addr + field_offset(mnt_namespace,root),"mnt_namespace root");
    if (!is_kvaddr(root_mount_addr)) return;
    parser_mount_tree(root_mount_addr,mount_list);
}

void FileSystem::parser_mount_tree(ulong mount_addr,std::vector<std::shared_ptr<Mount>>& mnt_list){
    std::shared_ptr<Mount> mnt_ptr = parser_mount(mount_addr);
    if(mnt_ptr->dir_name.empty()){
        mnt_ptr->dir_name = "None";
    }
    mnt_list.push_back(mnt_ptr);
    int offset = field_offset(mount, mnt_child);
    ulong list_head = mount_addr + field_offset(mount, mnt_mounts);
    for(auto& addr: for_each_list(list_head, offset)){
        parser_mount_tree(addr,mnt_ptr->childs);
    }
}

std::shared_ptr<Mount> FileSystem::parser_mount(ulong mount_addr){
    char buf[BUFSIZE];
    ulong name_addr = read_pointer(mount_addr + field_offset(mount,mnt_devname),"mount mnt_devname");
    if (!is_kvaddr(name_addr)) return nullptr;
    std::string dev_name = read_cstring(name_addr,64, "mnt_devname");
    ulong mountpoint_addr = read_pointer(mount_addr + field_offset(mount,mnt_mountpoint),"mount mnt_mountpoint");
    if (!is_kvaddr(mountpoint_addr)) return nullptr;
    ulong vfsmount_addr = mount_addr + field_offset(mount,mnt);
    if (!is_kvaddr(vfsmount_addr)) return nullptr;
    get_pathname(mountpoint_addr, buf, BUFSIZE, 1, vfsmount_addr);
    std::string dir_name = buf;
    ulong sb_addr = read_pointer(vfsmount_addr + field_offset(vfsmount,mnt_sb),"vfsmount mnt_sb");
    if (!is_kvaddr(sb_addr)) return nullptr;
    ulong fs_addr = read_pointer(sb_addr + field_offset(super_block,s_type),"super_block s_type");
    if (!is_kvaddr(fs_addr)) return nullptr;
    name_addr = read_pointer(fs_addr + field_offset(file_system_type,name),"file_system_type name");
    if (!is_kvaddr(name_addr)) return nullptr;
    std::string fs_type = read_cstring(name_addr,64, "file_system_type name");
    std::shared_ptr<Mount> mnt_ptr;
    if (fs_type == "f2fs"){
        mnt_ptr = std::make_shared<F2fs>();
    }else if (fs_type == "ext4"){
        mnt_ptr = std::make_shared<Ext4>();
    }else{
        mnt_ptr = std::make_shared<Mount>();
    }
    mnt_ptr->addr = mount_addr;
    mnt_ptr->dir_name = dir_name;
    mnt_ptr->dev_name = dev_name;
    mnt_ptr->sb_addr = sb_addr;
    mnt_ptr->fs_addr = fs_addr;
    mnt_ptr->fs_type = fs_type;
    mnt_ptr->mnt_flags = read_int(vfsmount_addr + field_offset(vfsmount,mnt_flags),"vfsmount mnt_flags");
    mnt_ptr->fs_info_addr = read_pointer(sb_addr + field_offset(super_block,s_fs_info),"super_block s_fs_info");
    if (sb_list.find(mnt_ptr->sb_addr) == sb_list.end()) { //not exists
        sb_list[mnt_ptr->sb_addr] = mnt_ptr;
    }
    return mnt_ptr;
}
#pragma GCC diagnostic pop
