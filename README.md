crash-plugins
=======

crash-plugins is a plugins of crash-utility tool. it add more extension plugin so that can parser more information from the ramdump,such as binder/device tree/memory etc.

For information about crash-utility, see the website:
    https://github.com/crash-utility/crash

Getting Started
------------
Clone this repo to extensions directory in crash-utility.

    git clone https://github.com/quic/crash-plugins.git  <path-to>/crash-utility/extensions

To build the plugins from the top-level crash-<version> directory, enter:

    make extensions

To load the plugin's commands to a running crash session, enter:

    crash> extend <path-to>/<plugin>.so

To show the plugin's commands, enter:

    crash> extend
    SHARED OBJECT            COMMANDS
    <path-to>/page_owner.so  owner

Help Pages
------------
### binder
    NAME
        binder - dump binder log information

    SYNOPSIS
        binder -a
        binder -p [pid]
        binder -l
        binder -f
        binder -n
        binder -b
        binder -t
        binder -r

    Display binder transaction log
    crash> binder -l
        4271996: reply from 21879:21893 to 1082:22054 context binder node 0 handle -1 size 52:8 ret 0/0 l=0
        4271997: call  from 1082:22054 to 874:0 context binder node 4266286 handle 21 size 352:8 ret 0/0 l=0
        4271964: reply from 1082:1082 to 874:1630 context binder node 0 handle -1 size 4:0 ret 0/0 l=0
        4271965: async from 1082:22057 to 21879:0 context binder node 4266113 handle 16 size 544:0 ret 0/0 l=0
        4271966: call  from 21879:22118 to 943:0 context binder node 4271723 handle 60 size 68:0 ret 0/0 l=0

    Display binder fail log
    crash> binder -f
        3881166: call  from 1082:4868 to 0:0 context binder node 0 handle 19 size 96:0 ret 29189/-22 l=3270
        3881198: call  from 1082:4868 to 0:0 context binder node 0 handle 27 size 96:0 ret 29189/-22 l=3270
        4004145: reply from 1057:4029 to 0:0 context binder node 0 handle -1 size 4:0 ret 29189/0 l=3201
        4246413: async from 1057:1706 to 21648:0 context binder node 4243445 handle 1013 size 1084:16 ret 29189/-3 l=3457

    Display all binder proc states
    crash> binder -a
        binder_proc:0xffffff804e636c00 eaurora.snapcam [21879] hwbinder dead:0 frozen:0 sr:0 ar:0 max:0 total:1 requested:0 started:0 ready:0
        binder_proc:0xffffff804e634c00 eaurora.snapcam [21879] hwbinder dead:0 frozen:0 sr:0 ar:0 max:0 total:4 requested:0 started:0 ready:1
        binder_proc:0xffffff800a72b400 eaurora.snapcam [21879] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:15 requested:0 started:5 ready:6

    Display binder thread info
    crash> binder -t
        binder_proc:0xffffff804e634c00 eaurora.snapcam [21879] hwbinder dead:0 frozen:0 sr:0 ar:0 max:0 total:4 requested:0 started:0 ready:1
            binder_thread:0xffffff80330b2800 pid:21926 loop:0 need_return:0
            binder_thread:0xffffff80330b3e00 pid:21879 loop:0 need_return:0
            binder_thread:0xffffff80341f4200 pid:21901 loop:0 need_return:0
            binder_thread:0xffffff80572a4000 pid:21928 loop:18 need_return:0

    Display binder node info
    crash> binder -n
        binder_proc:0xffffff804e634c00 eaurora.snapcam [21879] hwbinder dead:0 frozen:0 sr:0 ar:0 max:0 total:4 requested:0 started:0 ready:1
            binder_node:0xffffff80534df180 id:4266621 ptr:0xc11aa7a0 cookie:0xead90620 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:0 tr:0
            binder_node:0xffffff80610366c0 id:4266574 ptr:0xc11aa720 cookie:0xead90440 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:0 tr:0
            binder_node:0xffffff8061036480 id:4266557 ptr:0xc11aa280 cookie:0xead8ef00 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:0 tr:0

    Display binder ref info
    crash> binder -r
        binder_proc:0xffffff804e634c00 eaurora.snapcam [21879] hwbinder dead:0 frozen:0 sr:0 ar:0 max:0 total:4 requested:0 started:0 ready:1
            binder_ref:0xffffff8061250000 id:4250711 desc:7 s:1 w:1 death:0x0 -> node_id:1606 binder_proc:0xffffff8016f96000 mediaswcodec[1190]
            binder_ref:0xffffff804e760e00 id:4250606 desc:3 s:1 w:1 death:0x0 -> node_id:5319 binder_proc:0xffffff8013a6a000 vendor.qti.medi[909]
            binder_ref:0xffffff805811a700 id:4250579 desc:1 s:1 w:1 death:0x0 -> node_id:1549 binder_proc:0xffffff8013a6a000 vendor.qti.medi[909]
            binder_ref:0xffffff80510f3200 id:4250143 desc:0 s:1 w:1 death:0x0 -> node_id:10 binder_proc:0xffffff8017c66800 hwservicemanage[531]

    Display binder buffer info
    crash> binder -b
        binder_proc:0xffffff804e636c00 eaurora.snapcam [21879] hwbinder dead:0 frozen:0 sr:0 ar:0 max:0 total:1 requested:0 started:0 ready:0
        binder_alloc:0xffffff804e636dc0 mm_struct:0xffffff804e67ec00 vma:0xffffff801ad17780 buffer:0xc0e26000 size:1040384 free:520192
            Page :0xfffffffe01b1fa40 PA:0xac7e9000
            Free binder_buffer :0xffffff8041f7a500 id:0 data:0xc0e26008 PA:0xac7e9008 size:0 offset:0 extra:0 pid:0 delivered
            Alloc binder_buffer:0xffffff8047a55280 id:4251537 data:0xc0e26000 PA:0xac7e9000 size:4 offset:0 extra:0 pid:531 delivered

    Display specific process binder states
    crash> binder -p 21879
        binder_proc:0xffffff804e634c00 putmethod.latin [21879] hwbinder dead:0 frozen:0 sr:0 ar:0 max:0 total:4 requested:0 started:0 ready:1
            binder_thread:0xffffff80330b2800 pid:21926 loop:0 need_return:0
            binder_thread:0xffffff80330b3e00 pid:21879 loop:0 need_return:0
            binder_node:0xffffff80534df180 id:4266621 ptr:0xc11aa7a0 cookie:0xead90620 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:0 tr:0
            binder_node:0xffffff80610366c0 id:4266574 ptr:0xc11aa720 cookie:0xead90440 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:0 tr:0
            binder_node:0xffffff8061036480 id:4266557 ptr:0xc11aa280 cookie:0xead8ef00 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:0 tr:0
            binder_ref:0xffffff8061250000 id:4250711 desc:7 s:1 w:1 death:0x0 -> node_id:1606 binder_proc:0xffffff8016f96000 mediaswcodec[1190]
            binder_ref:0xffffff804e760e00 id:4250606 desc:3 s:1 w:1 death:0x0 -> node_id:5319 binder_proc:0xffffff8013a6a000 surfaceflinger[909]
            binder_ref:0xffffff805811a700 id:4250579 desc:1 s:1 w:1 death:0x0 -> node_id:1549 binder_proc:0xffffff8013a6a000 surfaceflinger[909]
            binder_alloc:0xffffff804e634dc0 mm_struct:0xffffff804e67ec00 vma:0xffffff80617420f0 buffer:0xc4278000 size:1040384 free:520192
                Page :0xfffffffe0130f200 PA:0x8c3c8000
                Free binder_buffer :0xffffff804e760080 id:4267933 data:0xc4278008 PA:0x8c3c8008 size:64 offset:0 extra:0 pid:1190 delivered
                Alloc binder_buffer:0xffffff80510f3580 id:4250147 data:0xc4278000 PA:0x8c3c8000 size:4 offset:0 extra:0 pid:531 delivered

    Display all binder info
    crash> binder -atnrb

### dts
    NAME
    dts - dump device tree info

    SYNOPSIS
    dts -a
    dts -f
    dts -b
    dts -n <name>
    dts -p <full path>
    dts -s

    Display whole dts info
    crash> dts -a
        {
                model=<xx Technologies, Inc. V1.1>;
                compatible=<xx,xx>;
                interrupt-parent=< 0x1 >;
                #address-cells=< 0x2 >;
                #size-cells=< 0x2 >;
        }

    Display whole dts info with address
    crash> dts -f
    ffffff806f290ac8:{
            ffffff806f290bc8:model=<xx Technologies, Inc. V1.1>;
            ffffff806f290c28:compatible=<xx,xx>;
            ffffff806f290ce8:interrupt-parent=< 0x1 >;
            ffffff806f290d48:#address-cells=< 0x2 >;
            ffffff806f290da8:#size-cells=< 0x2 >;
    }

    Display one node info by node name
    crash> dts -n memory
        memory{
                ddr_device_type=< 0x7 >;
                device_type=<memory>;
                reg=< 0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000 >;
        };

    Display one node info by node full path
    crash> dts -p /memory
        memory{
                ddr_device_type=< 0x7 >;
                device_type=<memory>;
                reg=< 0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000 >;
        };

    Display physic memory total size
    crash> dts -s
        =========================================
        0x40000000~0x7ee00000          size:0x3ee00000
        0x80000000~0xc0000000          size:0x40000000
        =========================================
        Total size:    2030M

    Read out the whole dtb memory
    crash>  dts -b ./dts.dtb
        initial_boot_params:fffffffdfdc65000
        save dtb to ./dts.dtb

### mm
    NAME
    mm - dump memory info

    SYNOPSIS
    mm -v
    mm -c
    mm -r
    mm -m
    mm -b
    mm -d
    mm -s

    Display cma memory info
    crash> mm -c
        ==============================================================================================================
        [0]  mem_dump_region                       cma:0xffffffd0e2e16268 PFN:0xbf800~0xc0000       size:8.00MB     used:0B         order:0
        [1]  user_contig_region                    cma:0xffffffd0e2e16328 PFN:0xbe800~0xbf800       size:16.00MB    used:0B         order:0
        [2]  adsp_region                           cma:0xffffffd0e2e163e8 PFN:0xbe000~0xbe800       size:8.00MB     used:2.20MB     order:0
        [3]  linux,cma                             cma:0xffffffd0e2e164a8 PFN:0xbc000~0xbe000       size:32.00MB    used:12.38MB    order:0
        [4]  non_secure_display_region             cma:0xffffffd0e2e16628 PFN:0xb0c00~0xbb000       size:164.00MB   used:0B         order:0
        ==============================================================================================================
        Total:264.00MB allocated:15.78MB

    Display reserved memory info
    crash> mm -r
        ==============================================================================================================
        [0]  mem_dump_region                       reserved_mem:0xffffffd0e2ed4a88 range:0xbf800000~0xc0000000    size:8.00MB     [reusable]
        [1]  user_contig_region                    reserved_mem:0xffffffd0e2ed4ac0 range:0xbe800000~0xbf800000    size:16.00MB    [reusable]
        [2]  adsp_region                           reserved_mem:0xffffffd0e2ed4af8 range:0xbe000000~0xbe800000    size:8.00MB     [reusable]
        [3]  linux,cma                             reserved_mem:0xffffffd0e2ed4b30 range:0xbc000000~0xbe000000    size:32.00MB    [reusable]
        [4]  qseecom_region                        reserved_mem:0xffffffd0e2ed4bd8 range:0xaf800000~0xb0c00000    size:20.00MB    [reusable]
        [5]  oda_region@45700000                   reserved_mem:0xffffffd0e2ed4c10 range:0x45700000~0x45a00000    size:3.00MB     [no-map]
        [6] video_region@50900000                 reserved_mem:0xffffffd0e2ed4dd0 range:0x50900000~0x51000000    size:7.00MB     [no-map]
        [7] adsp_regions@51000000                 reserved_mem:0xffffffd0e2ed4e08 range:0x51000000~0x52900000    size:25.00MB    [no-map]
        [8] gpu_region@52915000                   reserved_mem:0xffffffd0e2ed4eb0 range:0x52915000~0x52917000    size:8.00KB     [no-map]
        [9] splash_region@5c000000                reserved_mem:0xffffffd0e2ed4ee8 range:0x5c000000~0x5cf00000    size:15.00MB    [unknow]
        [10] dfps_data_region@5cf00000             reserved_mem:0xffffffd0e2ed4f20 range:0x5cf00000~0x5d000000    size:1.00MB     [unknow]
        [11] stats_region@60000000                 reserved_mem:0xffffffd0e2ed4f58 range:0x60000000~0x60100000    size:1.00MB     [no-map]
        [12] removed_region@60100000               reserved_mem:0xffffffd0e2ed4f90 range:0x60100000~0x61f00000    size:30.00MB    [no-map]
        ==============================================================================================================
        Total:448.20MB nomap:168.20MB reuse:264.00MB other:16.00MB

    Display memblock memory info
    crash> mm -m
        memblock_type:0xffffffd0e27f6160 [memory] size:1.98GB
        [0]  memblock_region:0xffffffd0e28ff550 range:0x40000000~0x45700000         size:87.00MB    flags:MEMBLOCK_NONE
        [1]  memblock_region:0xffffffd0e28ff568 range:0x45700000~0x45f1b000         size:8.11MB     flags:MEMBLOCK_NOMAP
        [2]  memblock_region:0xffffffd0e28ff580 range:0x45f1b000~0x45fff000         size:912.00KB   flags:MEMBLOCK_NONE

        memblock_type:0xffffffd0e27f6188 [reserved] size:356.42MB
        [0]  memblock_region:0xffffffd0e2900150 range:0x40010000~0x430f1000         size:48.88MB    flags:MEMBLOCK_NONE
        [1]  memblock_region:0xffffffd0e2900168 range:0x430f4000~0x43100000         size:48.00KB    flags:MEMBLOCK_NONE
        [2]  memblock_region:0xffffffd0e2900180 range:0x44a65000~0x44aaf299         size:296.65KB   flags:MEMBLOCK_NONE

    Display buddy info
    crash> mm -b
        Free pages count per migrate type at order  [0-10]:
        Node(0)
        -----------------------------------------------------------------------------------------------------
                                        zone DMA32
        -----------------------------------------------------------------------------------------------------
            Order     4K     8K    16K    32K    64K   128K   256K   512K  1024K  2048K  4096K    Total
        Unmovable      9     43      0      0      0      0      0      0      0      0      0 380.00KB
            Movable    477    411      0      0      0      0      0      0      0      0      0   5.07MB
        Reclaimable      3      0      0      0      0      0      0      0      0      0      0  12.00KB
                CMA      0      0      0      0      0      0      0      0      0      0      0       0B
        HighAtomic      0      0      0      0      0      0      0      0      0      0      0       0B
            Isolate      0      0      0      0      0      0      0      0      0      0      0       0B
        -----------------------------------------------------------------------------------------------------

    Display dma_buf memory info
    crash> mm -d
        ==============================================================================================================
        [0]dma_buf:0xffffff8052c76600 [system] priv:0xffffff8054dd8600 f_count:3 size:4K
        dma_buf_attachment:0xffffff80685fda00 device:0xffffff80043b9010[61800000.qseecom] driver:0xffffffd0df1194b0[qseecom] priv:0xffffff803e382c40
        ==============================================================================================================
        total dma_buf size:227.35M

    Display vmalloc memory info
    crash>  mm -v
        vmap_area:0xffffff8003415980 range:0xffffffc008000000~0xffffffc008005000 size:20K
        vm_struct:0xffffff8003403a00 size:20K flags:vmalloc nr_pages:4 addr:0xffffffc008000000 phys_addr:0x0 init_IRQ+32
            Page:0xfffffffe000d2a00 PA:0x434a8000
            Page:0xfffffffe000d2a40 PA:0x434a9000
            Page:0xfffffffe000d2a80 PA:0x434aa000
            Page:0xfffffffe000d2ac0 PA:0x434ab000

    Display detail memory info
    crash> mm -s
        Memory config:
        =====================================================
        0x40000000~0x7ee00000          size:0x3ee00000
        0x80000000~0xc0000000          size:0x40000000
        =====================================================
        Total size:1.98GB


        Physic memory:
        ==============================================================================================================
        Node(ffffffd0e2830240) spanned:524288(2.00GB) present:519680(1.98GB) hole:4608(18.00MB) start_pfn:262144 start_paddr:40000000
        DMA32     zone(ffffffd0e2830240) spanned:524288(2.00GB) present:519680(1.98GB) hole:4608(18.00MB) managed:454335(1.73GB) reserved:65345(255.25MB) cma_pages:67584(264.00MB) start_pfn:262144
        Normal    zone(ffffffd0e28308c0) spanned:0(0B) present:0(0B) hole:0(0B) managed:0(0B) reserved:0(0B) cma_pages:0(0B) start_pfn:0
        Movable   zone(ffffffd0e2830f40) spanned:0(0B) present:0(0B) hole:0(0B) managed:0(0B) reserved:0(0B) cma_pages:0(0B) start_pfn:0
        ==============================================================================================================


        Memory breakdown:
        ====================================================
        RAM:                         2.00GB
        Carveout:                    18.00MB
        MemTotal:                    1.73GB
        MemFree:                  6.32MB
        Buffers:                  2.41MB
        Cached:                   366.83MB
        SwapCached:               8.29MB
        Active:                   446.28MB
            Anon:                 284.28MB
            File:                 162.00MB
        Inactive:                 301.62MB
            Anon:                 108.66MB
            File:                 192.96MB
        Slab:                     358.48MB
            SReclaimable:         155.35MB
            SUnreclaim:           203.12MB
        KernelStack:              33.78MB
        PageTables:               29.20MB
        Shmem:                    10.61MB
        Cma:                      15.78MB
        Vmalloc:                  112.97MB
        Dmabuf:                   227.35MB
        Reserved:                    255.25MB
        No-Map:                   168.20MB
        Static:                   87.05MB
            Struct Page:          29.09MB(476621)
            Kernel Code:          34.88MB
            Kernel Data:          8.69MB
            Dentry cache:         2.00MB
            Inode cache:          256.00KB
            Other:                12.15MB
        ====================================================

Tested Kernels
------------
+ 5.4 to 6.6

Related Links
------------
+ https://github.com/quic/crash-plugins.git

Author
------------
+ quic_wya@quicinc.com


Contributing
------------
