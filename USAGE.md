# How to use

Support command:

|  command                 | kernel 5.4  | kernel 5.15  |  kernel 6.1  | kernel 6.6   |       comment            |
|  --------                | --------    | --------     |  --------    |   --------   | -----------------        |
| [dts](#dts)              | √           | √            | √            | √            |  show device tree        |
| [cma](#cma)              | √           | √            | √            | √            |  show cma memory         |
| [reserved](#reserved)    | √           | √            | √            | √            |  show reserved memory    |
| [vmalloc](#vmalloc)      | √           | √            | √            | √            |  show vmalloc memory     |
| [memblock](#memblock)    | √           | √            | √            | √            |  show memblock memory    |
| [dmabuf](#dmabuf)        | √           | √            | √            | √            |  show dmabuf memory      |
| [iomem](#iomem)          | √           | √            | √            | √            |  show iomem memory       |
| [buddy](#buddy)          | √           | √            | √            | √            |  show buddy info         |
| [zram](#zram)            | √           | √            |              |              |  show zram memory        |
| [meminfo](#meminfo)      | √           | √            | √            | √            |  show process memory     |
| [procrank](#procrank)    | √           | √            | √            | √            |  show process memory     |
| [binder](#binder)        | √           | √            |              |              |  show binder info        |
| [slub](#slub)            | √           | √            |              |              |  show slub memory        |
| [dd](#dd)                | √           | √            | √            | √            |  show device driver info |
| [wq](#wq)                | √           | √            | √            | x            |  show workqueue          |
| [df](#df)                | √           | √            | √            | √            |  show mount info         |
| [pageowner](#pageowner)  | √           | √            |              |              |  show pageowner          |
| [swap](#swap)            | √           | √            |              |              |  show swap info          |
| [rtb](#rtb)              | √           | √            | x            | x            |  show rtb log            |
| [cpu](#cpu)              | √           | √            | √            | √            |  show cpu frequency      |
| [coredump](#coredump)    | √           | √            |              |              |  generate coredump       |
| [tm](#tm)                | √           | √            | √            | √            |  show thermal info       |
| [wdt](#wdt)              | √           | √            | √            | √            |  show watchdog info      |
| [cache](#cache)          | √           | √            | √            | √            |  show pagecache info     |
| [dbi](#dbi)              | √           | √            | √            | √            |  show debug image info   |
| [ipc](#ipc)              | √           | √            | √            | √            |  show ipc log            |
| [reg](#reg)              | √           | √            | √            | √            |  show regulator info     |
| [icc](#icc)              | √           | √            | √            | √            |  show icc info           |
| [ccf](#ccf)              | √           | √            | √            | √            |  show clock info         |
| [pstore](#pstore)        | √           | √            | √            | √            |  show pstore log         |


|  command                 |   Android-11(30)  |  Android-12(31) |  Android-13(33) |     comment           |
|  --------                | ----------------  | --------------- | --------------- | -----------------     |
| [prop](#prop)            | √                 | √               |                 | show property         |
| [logcat](#logcat)        | √                 | √               |                 | show logcat log       |


## memblock
This command is used to view detailed information about memblock.

### memblock -a
```
crash> memblock -a
membock_type:c1f39ed8 [memory] total_size:864.34MB
  [00000]memblock_region:c2172b68 range:[40000000~45a00000] size:90MB       flags:MEMBLOCK_NONE
  [00001]memblock_region:c2172b74 range:[45f10000~45fff000] size:956KB      flags:MEMBLOCK_NONE
  [00002]memblock_region:c2172b80 range:[46300000~4ab00000] size:72MB       flags:MEMBLOCK_NONE
  [00003]memblock_region:c2172b8c range:[52717000~60000000] size:216.91MB   flags:MEMBLOCK_NONE
  [00004]memblock_region:c2172b98 range:[60100000~60e00000] size:13MB       flags:MEMBLOCK_NONE
  [00005]memblock_region:c2172ba4 range:[61f00000~7f680000] size:471.50MB   flags:MEMBLOCK_NONE

memblock_type:c1f39eec [reserved] total_size:150.70MB
  [00000]memblock_region:c2173168 range:[40004000~40008000] size:16KB       flags:MEMBLOCK_NONE
  [00001]memblock_region:c2173174 range:[40100000~4277f094] size:38.50MB    flags:MEMBLOCK_NONE
  [00002]memblock_region:c2173180 range:[453b2000~453fe11e] size:304.28KB   flags:MEMBLOCK_NONE
  [00003]memblock_region:c217318c range:[455b3000~456ff000] size:1.30MB     flags:MEMBLOCK_NONE
  [00004]memblock_region:c2173198 range:[459fdf10~45a00000] size:8.23KB     flags:MEMBLOCK_NONE
  [00005]memblock_region:c21731a4 range:[5cf00000~5d000000] size:1MB        flags:MEMBLOCK_NONE
```
## reserved
This command is used to view detailed information about reserved memory.
### reserved -a
```
crash> reserved -a
==============================================================================================================
[000]deepsleep_region@45A00000  reserved_mem:c24a5fb4 range:[45a00000~45b00000] size:1MB      [no-map  ]
[001]hyp_region@45B00000        reserved_mem:c24a5fd0 range:[45b00000~45e00000] size:3MB      [no-map  ]
[002]xbl_aop_mem@45e00000       reserved_mem:c24a5fec range:[45e00000~45f10000] size:1.06MB   [no-map  ]
[003]sec_apps_region@45fff000   reserved_mem:c24a6008 range:[45fff000~46000000] size:4KB      [no-map  ]
[004]smem@46000000              reserved_mem:c24a6024 range:[46000000~46200000] size:2MB      [no-map  ]
[005]wlan_msa_region@46200000   reserved_mem:c24a6040 range:[46200000~46300000] size:1MB      [no-map  ]
[006]modem_region@4ab00000      reserved_mem:c24a605c range:[4ab00000~50900000] size:94MB     [no-map  ]
[007]pil_video_region@50900000  reserved_mem:c24a6078 range:[50900000~50e00000] size:5MB      [no-map  ]
[008]adsp_regions@50E00000      reserved_mem:c24a6094 range:[50e00000~52700000] size:25MB     [no-map  ]
[009]ips_fw_region@52700000     reserved_mem:c24a60b0 range:[52700000~52710000] size:64KB     [no-map  ]
[010]ipa_gsi_region@52710000    reserved_mem:c24a60cc range:[52710000~52715000] size:20KB     [no-map  ]
[011]gpu_region@52715000        reserved_mem:c24a60e8 range:[52715000~52717000] size:8KB      [no-map  ]
[012]splash_region@5c000000     reserved_mem:c24a6104 range:[5c000000~5cf00000] size:15MB     [unknow  ]
[013]dfps_data_region@5cf00000  reserved_mem:c24a6120 range:[5cf00000~5d000000] size:1MB      [unknow  ]
[014]stats_region@60000000      reserved_mem:c24a613c range:[60000000~60100000] size:1MB      [no-map  ]
[015]removed_region@60100000    reserved_mem:c24a6158 range:[60e00000~61f00000] size:17MB     [no-map  ]
[016]linux,cma                  reserved_mem:c24a5f98 range:[79000000~7b000000] size:32MB     [reusable]
[017]qseecom_ta_region          reserved_mem:c24a5f7c range:[7b000000~7c000000] size:16MB     [reusable]
[018]mem_dump_region            reserved_mem:c24a5f60 range:[7c000000~7c800000] size:8MB      [reusable]
[019]adsp_region                reserved_mem:c24a5f44 range:[7c800000~7d000000] size:8MB      [reusable]
[020]qseecom_region             reserved_mem:c24a5f28 range:[7d000000~7e400000] size:20MB     [reusable]
[021]user_contig_region         reserved_mem:c24a5f0c range:[7e400000~7f400000] size:16MB     [reusable]
==============================================================================================================
Total:266.16MB nomap:150.16MB reuse:100MB unknow:16MB
```
## cma
This command is used to view detailed information about cma memory.
### cma -a
View cma memory information
```
crash> cma -a
==============================================================================================================
[01]user_contig_region  cma:c2432db8 range:[7e400000~7f400000] size:16MB     used:0B       order:0
[02]qseecom_region      cma:c2432e04 range:[7d000000~7e400000] size:20MB     used:744KB    order:0
[03]adsp_region         cma:c2432e50 range:[7c800000~7d000000] size:8MB      used:2MB      order:0
[04]mem_dump_region     cma:c2432e9c range:[7c000000~7c800000] size:8MB      used:0B       order:0
[05]qseecom_ta_region   cma:c2432ee8 range:[7b000000~7c000000] size:16MB     used:0B       order:0
[06]linux,cma           cma:c2432f34 range:[79000000~7b000000] size:32MB     used:6.89MB   order:0
==============================================================================================================
Total:100MB allocated:9.61MB
```
### cma -u 'cma name'
View allocted pages of cma region with cma name.
```
crash> cma -u adsp_region

========================================================================
Name      : adsp_region
Base_pfn  : 7c800
End_pfn   : 7d000
Count     : 2048
Size      : 8MB
Bitmap    : f77d6200 ~ f77d6300
========================================================================
[00001]Pfn:7c800 Page:f848d000 paddr:7c800000 allocted
[00002]Pfn:7c801 Page:f848d024 paddr:7c801000 allocted
[00003]Pfn:7c802 Page:f848d048 paddr:7c802000 allocted
[00004]Pfn:7c803 Page:f848d06c paddr:7c803000 allocted
[00005]Pfn:7c804 Page:f848d090 paddr:7c804000 allocted
[00006]Pfn:7c805 Page:f848d0b4 paddr:7c805000 allocted
```

### cma -f 'cma name'
View free pages of cma region with cma name.
```
crash> cma -f adsp_region

========================================================================
Name      : adsp_region
Base_pfn  : 7c800
End_pfn   : 7d000
Count     : 2048
Size      : 8MB
Bitmap    : f77d6200 ~ f77d6300
========================================================================
[00001]Pfn:7ca00 Page:f8491800 paddr:7ca00000 free
[00002]Pfn:7ca01 Page:f8491824 paddr:7ca01000 free
[00003]Pfn:7ca02 Page:f8491848 paddr:7ca02000 free
[00004]Pfn:7ca03 Page:f849186c paddr:7ca03000 free
```
## buddy
This command is used to view detailed information about buddy memory.
### buddy -a
View all buddy memory information.
```
crash> buddy -a

Node(0)
---------------------------------------------------------------------------------------------------------------------------
                                             zone Normal
---------------------------------------------------------------------------------------------------------------------------
       Order      4KB      8KB     16KB     32KB     64KB    128KB    256KB    512KB      1MB      2MB      4MB      Total
   Unmovable       45      545      261      173       57        0        0        0        0        0        0    17.48MB
     Movable     2855      998       12        0        3        0        1        0        0        0        0    19.57MB
 Reclaimable        7        0       43        2        1        0        0        0        0        0        0      844KB
         CMA        0        0        0        0        0        0        0        0        0        0        0         0B
  HighAtomic        0        0        1        2        1        3        0        2        1        0        0     2.52MB
     Isolate        0        0        0        0        0        0        0        0        0        0        0         0B
       Total  11.36MB  12.05MB   4.95MB   5.53MB   3.88MB    384KB    256KB      1MB      1MB       0B       0B    40.39MB
---------------------------------------------------------------------------------------------------------------------------
```
### buddy -n
Display memory node info.
```
crash> buddy -n

Config:
---------------------------------------
min_free_kbytes          : 3350kB
user_min_free_kbytes     : 3350kB
watermark_scale_factor   : 1
---------------------------------------

Node:
=======================================
pglist_data(0): c2081180
  spanned           : 259712(1014.50MB)
  present           : 221272(864.34MB)
  hole              : 38440(150.16MB)
  start_pfn         : 40000
  start_paddr       : 40000000

  Normal zone:c2081180
    spanned         : 230656(901MB)
    present         : 192216(750.84MB)
    hole            : 38440(150.16MB)
    managed         : 180077(703.43MB)
    reserved        : 12139(47.42MB)
    start_pfn       : 40000
    start_paddr     : 40000000
    watermark_boost : 0
    WMARK_HIGH      : 1651(6.45MB)
    WMARK_LOW       : 1442(5.63MB)
    WMARK_MIN       : 837(3.27MB)
```
### buddy -z 'zone addr'
Display page info of zone.
crash> buddy -z c2081180
 ```
Order[0] 4KB
   migratetype:Unmovable Order[0]
     [00001]Page:f7cfc080 PA:46b20000
     [00002]Page:f80a6f78 PA:60c6e000
     [00003]Page:f7c76508 PA:42fb2000
     [00004]Page:f7fc7298 PA:5a8f6000
   migratetype:Movable Order[0]
     [00001]Page:f8066f94 PA:5effd000
     [00002]Page:f7d2068c PA:47b4b000
     [00003]Page:f8153d90 PA:65944000
     [00004]Page:f80e93c8 PA:629e2000
     [00005]Page:f803becc PA:5dcdb000
```
## procrank
This command dumps the process info. you must insmod the zram ko before run this command.

### procrank -a
```
crash> mod -s zram ./lib/zram.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d3758440  zram                       ffffffd4d3752000     49152  ./lib/zram.ko
crash> mod -s zsmalloc ./lib/zsmalloc.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d34c6200  zsmalloc                   ffffffd4d34bf000     57344  ./lib/zsmalloc.ko

crash> procrank -a
PID      Vss        Rss        Pss        Uss        Swap       Comm
2023     1.25GB     85.30MB    24.93MB    11.47MB    34.68MB    com.android.systemui
1067     2.41GB     84.20MB    20.58MB    6.70MB     47.02MB    system_server
4067     1.01GB     64.66MB    10.31MB    1.38MB     25.33MB    com.qualcomm.qti.weartech.watchface
4268     1.06GB     62.55MB    12.78MB    3.62MB     22.26MB    com.android.settings
4088     1.00GB     58.61MB    8.34MB     1.11MB     25.54MB    com.android.inputmethod.latin
3866     1.50GB     42.37MB    5.44MB     328KB      23.07MB    com.android.commands.monkey
2807     1.03GB     42.34MB    3.34MB     240KB      26.62MB    com.android.providers.media.module
712      1.66GB     39.58MB    2.66MB     40KB       24.52MB    zygote
2278     1017.48MB  36.51MB    2.11MB     0B         25.37MB    com.qualcomm.qti.standby
2348     1.04GB     36.39MB    2.08MB     8KB        32.59MB    com.android.phone
2828     1.00GB     36.23MB    1.90MB     4KB        25.74MB    com.android.nfc
2143     1022.46MB  35.62MB    1.87MB     4KB        26.03MB    com.android.networkstack.process
2281     1.00GB     34.75MB    1.72MB     4KB        25.66MB    .qtidataservices
2851     1020.70MB  34.48MB    1.75MB     8KB        28.47MB    com.qualcomm.location
2865     1021.14MB  34.44MB    1.68MB     0B         25.35MB    com.qti.diagservices
2292     1017.32MB  33.75MB    1.64MB     0B         25.34MB    com.qualcomm.qti.aonutility
```

### procrank -c
```
crash> mod -s zram ./lib/zram.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d3758440  zram                       ffffffd4d3752000     49152  ./lib/zram.ko
crash> mod -s zsmalloc ./lib/zsmalloc.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d34c6200  zsmalloc                   ffffffd4d34bf000     57344  ./lib/zsmalloc.ko

crash> procrank -c
PID      Comm                 Cmdline
1        init                 /system/bin/init
```

## vmalloc
This command dumps the vmalloc info.

### vmalloc -a
Display vmalloc memory info
```
crash> vmalloc -a
[0000]vmap_area:ffffff8003015540 range:[ffffffc008000000~ffffffc008005000] size:20KB
   vm_struct:ffffff8003003a00 size:20KB flags:vmalloc nr_pages:4 addr:ffffffc008000000 phys_addr:0 start_kernel+496
       [0001]Page:fffffffe000c2a00 PA:430a8000
       [0002]Page:fffffffe000c2a40 PA:430a9000
       [0003]Page:fffffffe000c2a80 PA:430aa000
       [0004]Page:fffffffe000c2ac0 PA:430ab000

[0001]vmap_area:ffffff8003015a00 range:[ffffffc008005000~ffffffc008007000] size:8KB
   vm_struct:ffffff8003003c40 size:8KB flags:vmalloc nr_pages:1 addr:ffffffc008005000 phys_addr:0 init_IRQ+344
       [0001]Page:fffffffe000c2ec0 PA:430bb000
```
### vmalloc -r
Display all vmap_area info
```
crash> vmalloc -r
Total vm size:416.71MB
==============================================================================================================
[0000]vmap_area:ffffff8003015540 range:[ffffffc008000000~ffffffc008005000] size:20KB
[0001]vmap_area:ffffff8003015a00 range:[ffffffc008005000~ffffffc008007000] size:8KB
[0002]vmap_area:ffffff8003015940 range:[ffffffc008008000~ffffffc00800d000] size:20KB
[0003]vmap_area:ffffff8003015500 range:[ffffffc00800d000~ffffffc00800f000] size:8KB
[0004]vmap_area:ffffff8003015880 range:[ffffffc008010000~ffffffc008015000] size:20KB
[0005]vmap_area:ffffff8003015980 range:[ffffffc008015000~ffffffc008017000] size:8KB
```
### vmalloc -v
Display all vm_struct info
```
crash> vmalloc -v
Total vm size:475.16MB, physical size:101.41MB
==============================================================================================================
[0000]vm_struct:ffffff8003003a00 size:20KB     flags:vmalloc  nr_pages:4    kaddr:ffffffc008000000 phys_addr:0
[0001]vm_struct:ffffff8003003c40 size:8KB      flags:vmalloc  nr_pages:1    kaddr:ffffffc008005000 phys_addr:0
[0002]vm_struct:ffffff8003003ac0 size:20KB     flags:vmalloc  nr_pages:4    kaddr:ffffffc008008000 phys_addr:0
[0003]vm_struct:ffffff8003003cc0 size:8KB      flags:vmalloc  nr_pages:1    kaddr:ffffffc00800d000 phys_addr:0
```

### vmalloc -s
Display vmalloc statistical info
```
crash> vmalloc -s
Summary by caller:
========================================================
Func Name                                    virt            phys
map_lowmem                                   1.24GB          0B
__devm_ioremap+92                            56.38MB         0B
pmd_empty_section_gap                        35MB            0B
tmc_alloc_sg_table+184                       32.00MB         0B
pci_reserve_io                               24MB            0B
av8l_fast_alloc_pgtable+964                  12.02MB         0B
load_module+3876                             9.41MB          9.30MB

Summary by type:
========================================================
Type      virt            phys
unknow    1.24GB          0B
ioremap   143.93MB        0B
vmap      35.86MB         0B
vmalloc   21.27MB         18.20MB
vpages    10.12MB         0B

```
### vmalloc -f 'func name'
Display the allocated pages by function name
```
crash> vmalloc -f load_module
[0001]Page:fffffffe0054f780 PA:553de000
[0002]Page:fffffffe0054f740 PA:553dd000
[0003]Page:fffffffe00588a80 PA:5622a000
[0004]Page:fffffffe00588ac0 PA:5622b000
[0005]Page:fffffffe0065da80 PA:5976a000
[0006]Page:fffffffe007a3c40 PA:5e8f1000
```

### vmalloc -t 'type name'
Display vmalloc statistical info
```
crash> vmalloc -t vmalloc
[0001]Page:fffffffe000c2a00 PA:430a8000
[0002]Page:fffffffe000c2a40 PA:430a9000
[0003]Page:fffffffe000c2a80 PA:430aa000
[0004]Page:fffffffe000c2ac0 PA:430ab000
[0005]Page:fffffffe000c2ec0 PA:430bb000
```

## dmabuf
This command dumps the dmabuf information.

### dmabuf -b
Display all dmabuf.
```
crash> dmabuf -b
=======================================================================================
[001]dma_buf:c95483cc ref:2  priv:c31f9a80 ops::dma_buf_ops  [ion_dma_buf] size:648KB
[002]dma_buf:c87163cc ref:6  priv:c9d26e80 ops::dma_buf_ops  [ion_dma_buf] size:648KB
[003]dma_buf:db095c4c ref:6  priv:d72dbe80 ops::dma_buf_ops  [ion_dma_buf] size:648KB
=======================================================================================
Total size:12.89MB
```

### dmabuf -B 'dma_buf address'
Display the dmabuf detail info by dma_buf address.
```
crash> dmabuf -B c95483cc
dma_buf:c95483cc ref:2  priv:c31f9a80  [ion_dma_buf] sg_table:d6d4bd00 size:648KB
        pid:604   [allocator-servi] fd:7
        pid:632   [surfaceflinger] fd:35
        scatterlist:c3d94000 page:ec606740 offset:0 length:4KB dma_address:55350000 dma_length:0B
        scatterlist:c3d94014 page:ec47924c offset:0 length:4KB dma_address:4a2bb000 dma_length:0B
        scatterlist:c3d94028 page:ec3cf0a4 offset:0 length:4KB dma_address:45721000 dma_length:0B

```

### dmabuf -h
Display all heap info.
```
Id  ion_heap   type                   Name          flags  ops                      buf_cnt total_size
25  e8514008                          system        1      system_heap_ops          44      12.16MB
10  e9021a10                          secure_heap   0      system_secure_heap_ops   0       0B
6   e9a96808   ION_HEAP_TYPE_DMA      user_contig   0      ion_cma_ops              0       0B
7   e9a97408   ION_HEAP_TYPE_DMA      qsecom        0      ion_cma_ops              12      752KB
1   e9a96b08   ION_HEAP_TYPE_DMA      qsecom_ta     0      ion_cma_ops              0       0B

```

### dmabuf -H 'heap name'
Display the dmabuf detail info by heap name.
```
crash> dmabuf -H system
dma_buf:c95491cc ref:4  priv:c31f8680  [ion_dma_buf] sg_table:d3617080 size:32KB
        pid:604   [allocator-servi] fd:8
        pid:632   [surfaceflinger] fd:99
        scatterlist:c9548200 page:ec5d63ec offset:0 length:4KB dma_address:53de3000 dma_length:0B
        scatterlist:c9548214 page:ec5de54c offset:0 length:4KB dma_address:5417b000 dma_length:0B
        scatterlist:c9548228 page:ec8ef364 offset:0 length:4KB dma_address:69e51000 dma_length:0B
        scatterlist:c954823c page:ec639a40 offset:0 length:4KB dma_address:56a10000 dma_length:0B
        scatterlist:c9548250 page:ec3bc954 offset:0 length:4KB dma_address:44eed000 dma_length:0B
        scatterlist:c9548264 page:ec472de4 offset:0 length:4KB dma_address:49ff1000 dma_length:0B
        scatterlist:c9548278 page:ec3b2580 offset:0 length:4KB dma_address:44a60000 dma_length:0B
        scatterlist:c954828c page:ec472dc0 offset:0 length:4KB dma_address:49ff0000 dma_length:0B
```

### dmabuf -p
Display dmabuf size of process.
```
crash> dmabuf -p
PID   Comm                 buf_cnt  total_size
604   allocator-servi      2        680KB
605   composer-servic      22       7.30MB
632   surfaceflinger       34       10.66MB
```

### dmabuf -P 'pid'
Display the dmabuf detail info by pid.
```
crash> dmabuf -P 632
dma_buf:db0951cc ref:9  priv:d616bc80  [ion_dma_buf] sg_table:c9a871c0 size:32KB
        pid:605   [composer-servic] fd:33
        pid:632   [surfaceflinger] fd:100
        pid:1670  [arable.launcher] fd:135
        scatterlist:d6fc7380 page:ec41a854 offset:0 length:4KB dma_address:478ad000 dma_length:0B
        scatterlist:d6fc7394 page:ec4851b0 offset:0 length:4KB dma_address:4a80c000 dma_length:0B
        scatterlist:d6fc73a8 page:ec62b2a4 offset:0 length:4KB dma_address:563a1000 dma_length:0B
        scatterlist:d6fc73bc page:ec70835c offset:0 length:4KB dma_address:5c5df000 dma_length:0B
        scatterlist:d6fc73d0 page:ec5d932c offset:0 length:4KB dma_address:53f33000 dma_length:0B
        scatterlist:d6fc73e4 page:ec65690c offset:0 length:4KB dma_address:576eb000 dma_length:0B
        scatterlist:d6fc73f8 page:ec430c1c offset:0 length:4KB dma_address:4828f000 dma_length:0B
        scatterlist:d6fc740c page:ec447098 offset:0 length:4KB dma_address:48c76000 dma_length:0B
```

### dmabuf -s
Display the memory pool of system heap.
```
crash> dmabuf -s
system:
   page_pool          order high       low        total
   ffffff8024374a80   9     0B         108MB      108MB
   ffffff8024374240   4     0B         79.69MB    79.69MB
   ffffff80243743c0   0     0B         368KB      368KB
```

### dmabuf -S 'dma_buf address'
Save a dmabuf data to file.
```
crash> dmabuf -S ffffff881ced9400
Save dmabuf to file ./dma_buf@ffffff881ced9400.data !
```
## iomem
This command dumps the memory layout information.

### iomem -a
```
crash> iomem -a
17179869184GB [0~ffffffffffffffff] PCI mem
        3.00MB    [500000~7fffff] 500000.pinctrl pinctrl@500000
        1.87MB    [1400000~15dffff] 1400000.clock-controller cc_base
        8.00KB    [1610000~1611fff] 1610000.msm-eud eud_base
        3B        [1612000~1612003] 1613000.hsphy eud_enable_reg
        287B      [1613000~161311f] 1613000.hsphy hsusb_phy_base
        376.50KB  [1880000~18de1ff] 1880000.interconnect interconnect@1880000
        4.00KB    [1900000~1900fff] 1900000.interconnect interconnect@1900000
        28.00KB   [1b40000~1b46fff] 1b40000.qfprom qfprom@1b40000
        152.00KB  [1c0a000~1c2ffff] spmi-0 cnfg
```
## meminfo
This command dumps the memory information.

### meminfo -a
Display whole memory info.
```
crash> meminfo -a
MemTotal:         1849960 KB
MemFree:           491092 KB
MemAvailable:      548164 KB
Buffers:             1420 KB
Cached:            268632 KB
SwapCached:           580 KB
Active:            580572 KB
Inactive:          287124 KB
Active(anon):      437992 KB
Inactive(anon):    167244 KB
Active(file):      142580 KB
Inactive(file):    119880 KB
Unevictable:         2660 KB
Mlocked:             2656 KB
SwapTotal:              0 KB
SwapFree:               0 KB
Dirty:                196 KB
Writeback:              0 KB
AnonPages:         599768 KB
Mapped:            171416 KB
Shmem:               6296 KB
KReclaimable:      112088 KB
Slab:                1160 KB
SReclaimable:         580 KB
SUnreclaim:           580 KB
KernelStack:         2769 KB
PageTables:             0 KB
NFS_Unstable:           0 KB
Bounce:                 0 KB
WritebackTmp:           0 KB
CommitLimit:       924980 KB
VmallocTotal:     1835008 KB
VmallocUsed:        20404 KB
VmallocChunk:           0 KB
Percpu:              2784 KB
CmaTotal:          102400 KB
CmaFree:                0 KB
```
### meminfo -b
Breakdown memory info.
```
crash> meminfo -b
RAM                :     11.28GB
   MemTotal        :     10.98GB
   MemFree         :      5.30GB
   Buffers         :      9.59MB
   Cached          :      2.06GB
   SwapCached      :          0B
   AonPage         :      1.20GB
   FilePage        :      1.93GB
   Slab            :    962.71MB
   KernelStack     :     56.22MB
   PageTables      :    123.91MB
   Shmem           :     35.79MB
   Cma             :       604MB
   Dmabuf          :    143.18MB
   Vmalloc         :    171.66MB
   Other           :      1.08GB

   Struct Page     :    671.64MB
   Kernel Code     :     29.44MB
   Kernel Data     :     14.50MB
   Dentry Cache    :        16MB
   Inode  Cache    :        32KB

   NON_HLOS        :    481.45MB
```
### meminfo -v
Breakdown vmstat info.
```
crash> meminfo -v
Zone (DMA)                   Pages |       Size
present_pages:              524288 |   2048.0 MB
spanned_pages:              524288 |   2048.0 MB
managed_pages:              437462 |   1708.8 MB
cma_pages:                    8192 |     32.0 MB
... ...
WMARK_HIGH:                   3762 |     14.7 MB
WMARK_LOW:                    3135 |     12.2 MB
WMARK_MIN:                    2508 |      9.8 MB
WMARK_PROMO:                  4389 |     17.1 MB
NR_ZSPAGES:                      0 |      0.0 MB

Zone (Normal)                Pages |       Size
present_pages:             1554432 |   6072.0 MB
spanned_pages:             1554432 |   6072.0 MB
managed_pages:             1513233 |   5911.1 MB
cma_pages:                       0 |      0.0 MB
... ...
WMARK_HIGH:                  13131 |     51.3 MB
WMARK_LOW:                   10943 |     42.7 MB
WMARK_MIN:                    8755 |     34.2 MB
WMARK_PROMO:                 15319 |     59.8 MB
NR_ZSPAGES:                      3 |      0.0 MB

Global Stats                 Pages |       Size
NR_BOUNCE:                       0 |      0.0 MB
NR_FREE_CMA_PAGES:            7424 |     29.0 MB
NR_FREE_PAGES:             1776755 |   6940.4 MB
... ...
NR_ZSPAGES:                      3 |      0.0 MB

Node Stats                   Pages |       Size
NR_ACTIVE_ANON:                252 |      1.0 MB
NR_ACTIVE_FILE:              10066 |     39.3 MB
NR_ANON_MAPPED:              23535 |     91.9 MB
NR_ANON_THPS:                 9728 |     38.0 MB
... ...
NR_SLAB_RECLAIMABLE_B:       22097 |     86.3 MB
NR_SLAB_UNRECLAIMABLE_B:     29234 |    114.2 MB


VM EVENT Stats               Pages |       Size
PGACTIVATE:                  10054 |     39.3 MB
PGALLOC_NORMAL:             650263 |   2540.1 MB
PGFAULT:                    423976 |   1656.2 MB
PGFREE:                    2433164 |   9504.5 MB
... ...
PGMIGRATE_SUCCESS:               0 |      0.0 MB
PGPGIN:                     353158 |   1379.5 MB
UNEVICTABLE_PGCULLED:         9094 |     35.5 MB

```
## zram
This command dumps the zram info.

### zram -a
Display all zram info
```
crash> zram -a
========================================================================
zram                : ffffff801530dc00
name                : zram0
compressor          : lz4 rle
total_size          : 1.50GB
zs_pool             : ffffff805bad4000
orig_data_size      : 291.87MB
compr_data_size     : 88.53MB
compress ratio      : 30.33%
mem_used_max        : 93.48MB
mem_used_total      : 93.47MB
mem_limit           : 0B
same_pages          : 23.81MB
huge_pages          : 7.67MB
compacted_pages     : 17.56MB
========================================================================
```
### zram -m 'zram addr'
Display the memory pool of specified zram by zram address
```
crash> zram -m ffffff801530dc00
zs_pool             : ffffff805bad4000
name                : zram0
pages_allocated     : 23929
isolated_pages      : 0
pages_compacted     : 4495
=============================================================================================
index size_class       EMPTY ALMOST_EMPTY ALMOST_FULL  FULL  pages/zspage objs/zspage  obj_size  OBJ_ALLOCATED OBJ_USED
00000 ffffff805b0b7000 0     0            0            0     1            128          32B       0             0
00001 ffffff805b0b7300 0     1            2            7     3            256          48B       2560          2368
00002 ffffff805b0b7480 0     1            3            19    1            64           64B       1472          1444
00003 ffffff805b0b7f00 0     0            1            22    1            51           80B       1173          1168
00004 ffffff805b0b7cc0 0     0            1            6     3            128          96B       896           888
00005 ffffff805b0b7840 0     1            1            9     2            73           112B      803           782
00006 ffffff805b0b7a80 0     1            0            15    1            32           128B      512           501
00007 ffffff805b0b73c0 0     1            1            3     3            85           144B      425           382
```

### zram -f 'zram addr'
Display the full info of specified zram by zram address
```
crash> zram -f ffffff801530dc00
size_class(ffffff805b0b7300) objs_per_zspage:256 pages_per_zspage:3 size:48
   zspage[0]:ffffff805414f400 freeobj:66 inuse:66 class:1 fullness:1
       page[0]:fffffffe01e2b880 PFN:b8ae2 range:b8ae2000-b8ae3000 offset:0
           obj[000000]b8ae2000~b8ae2030 handle:ffffff8068ea93d0 index:0    alloc
           obj[000001]b8ae2030~b8ae2060 handle:ffffff8068d795e0 index:1    alloc
           obj[000002]b8ae2060~b8ae2090 handle:ffffff8013df55e0 index:2    alloc
           obj[000003]b8ae2090~b8ae20c0 handle:ffffff806b06ccd0 index:3    alloc
           obj[000004]b8ae20c0~b8ae20f0 handle:ffffff8068e612e0 index:4    alloc
           obj[000005]b8ae20f0~b8ae2120 handle:ffffff805b884520 index:5    alloc
```

### zram -p 'zram addr'
Display all pages of specified zram by zram address
```
crash> zram -p ffffff801530dc00
Page[00001]:fffffffe01e2b880 PFN:b8ae2 range:[b8ae2000-b8ae3000] offset:0
Page[00002]:fffffffe01f980c0 PFN:be603 range:[be603000-be604000] offset:32
Page[00003]:fffffffe01cf6440 PFN:b3d91 range:[b3d91000-b3d92000] offset:16
Page[00004]:fffffffe01e70c40 PFN:b9c31 range:[b9c31000-b9c32000] offset:0
Page[00005]:fffffffe01ef79c0 PFN:bbde7 range:[bbde7000-bbde8000] offset:32
Page[00006]:fffffffe01ee2000 PFN:bb880 range:[bb880000-bb881000] offset:16
Page[00007]:fffffffe01d6efc0 PFN:b5bbf range:[b5bbf000-b5bc0000] offset:0
Page[00008]:fffffffe01d54580 PFN:b5516 range:[b5516000-b5517000] offset:32
```

### zram -z 'zram addr'
Display all zspage of specified zram by zram address
```
crash> zram -z ffffff801530dc00
zspage[00001]:ffffff805414f400 class:1   fullness:1 pages:3 inuse:66    freeobj:66
zspage[00002]:ffffff8067f162b0 class:1   fullness:2 pages:3 inuse:255   freeobj:101
zspage[00003]:ffffff806578c780 class:1   fullness:2 pages:3 inuse:255   freeobj:235
zspage[00004]:ffffff8068ca4240 class:1   fullness:3 pages:3 inuse:256   freeobj:2147483647
zspage[00005]:ffffff8067fd7780 class:1   fullness:3 pages:3 inuse:256   freeobj:2147483647
zspage[00006]:ffffff8069481470 class:1   fullness:3 pages:3 inuse:256   freeobj:2147483647
zspage[00007]:ffffff8067b21d30 class:1   fullness:3 pages:3 inuse:256   freeobj:2147483647
```

### zram -o 'size_class/zspage/page addr'
Display all obj info by zs_class/zspage/page address
```
crash> zram -o ffffff805414f400
           obj[000000]b8ae2000~b8ae2030 handle:ffffff8068ea93d0 index:0    alloc
           obj[000001]b8ae2030~b8ae2060 handle:ffffff8068d795e0 index:1    alloc
           obj[000002]b8ae2060~b8ae2090 handle:ffffff8013df55e0 index:2    alloc
           obj[000003]b8ae2090~b8ae20c0 handle:ffffff806b06ccd0 index:3    alloc
           obj[000004]b8ae20c0~b8ae20f0 handle:ffffff8068e612e0 index:4    alloc
           obj[000005]b8ae20f0~b8ae2120 handle:ffffff805b884520 index:5    alloc
```
## slub
This command dumps the slab info.

### slub -a
Display all slab info
```
crash> slub -a
kmem_cache:0xe2aeb880 adreno_dispatch_job
   kmem_cache_node:0xe2b96040 nr_partial:4 nr_slabs:4 total_objects:84
       slab:0xec3b65a0 order:0 VA:[0xc4c28000~0xc4c29000] totalobj:21 inuse:0 freeobj:21
           obj[00001]VA:[0xc4c28000~0xc4c280c0] status:freed
           obj[00002]VA:[0xc4c280c0~0xc4c28180] status:freed
           obj[00003]VA:[0xc4c28180~0xc4c28240] status:freed
           obj[00004]VA:[0xc4c28240~0xc4c28300] status:freed
```

### slub -s
Display slab memory info
```
crash> slub -s
kmem_cache name                    slabs slab_size  per_slab_obj total_objs obj_size   pad_size align_size total_size
eb00c280 kmalloc-64                4792  8KB        25           119176     64B        64       320B     36.37MB
eb0e1fc0 vm_area_struct            3623  8KB        25           87247      136B       8        320B     26.63MB
eb00f400 kmalloc-4k                1127  32KB       2            2242       4KB        4096     12KB     26.27MB
eb0e1240 inode_cache               1202  16KB       24           26310      472B       8        656B     16.46MB
eb0edfc0 kernfs_node_cache         1990  8KB        30           59595      88B        8        272B     15.46MB
```

### slub -c 'cache addr'
Display specified slab info by kmem_cache addr
```
crash> slub -c eb0e1fc0
kmem_cache:0xeb0e1fc0 vm_area_struct
   kmem_cache_node:0xeb081080 nr_partial:960 nr_slabs:3623 total_objects:87247
       slab:0xec7481d8 order:1 VA:[0xde246000~0xde248000] totalobj:25 inuse:6 freeobj:19
           obj[00001]VA:[0xde246000~0xde246140] status:freed
           obj[00002]VA:[0xde246140~0xde246280] status:freed
           obj[00003]VA:[0xde246280~0xde2463c0] status:freed
           obj[00004]VA:[0xde2463c0~0xde246500] status:freed
```

### slub -p
Check all slab cache poison info
```
crash> slub -p
kmem_cache_name           Poison_Result
kmalloc-64                PASS
vm_area_struct            PASS
kmalloc-4k                PASS
```

### slub -P 'cache addr'
Check specified slab cache poison info
```
crash> slub -P eb0e1fc0
kmem_cache_name           Poison_Result
vm_area_struct            PASS
```

### slub -l
Display the all of slub trace, include alloc and free
```
crash> slub -l
stack_id:2132518711 Allocated:56725 times kmem_cache:avtab_node size:10.82MB
   [<c04fa5b0>] avtab_insert_node+2c
   [<c04fb20c>] avtab_insertf+174
   [<c04faebc>] avtab_read_item+3ac
   [<c04fb004>] avtab_read+98
   [<c04fbf48>] policydb_read+568
   [<c0502538>] security_load_policy+d0
   [<c04f5720>] sel_write_load+138
   [<c0300858>] vfs_write+c4
   [<c0300a58>] ksys_write+68
   [<c0101000>] __hyp_idmap_text_end+0
```
### slub -t A
Display the all alloc trace.
```
crash> slub -t A
stack_id:2132518711 Allocated:56725 times kmem_cache:avtab_node size:10.82MB
   [<c04fa5b0>] avtab_insert_node+2c
   [<c04fb20c>] avtab_insertf+174
   [<c04faebc>] avtab_read_item+3ac
   [<c04fb004>] avtab_read+98
   [<c04fbf48>] policydb_read+568
   [<c0502538>] security_load_policy+d0
   [<c04f5720>] sel_write_load+138
   [<c0300858>] vfs_write+c4
   [<c0300a58>] ksys_write+68
   [<c0101000>] __hyp_idmap_text_end+0
```
### slub -t F
Display the all free trace.
```
crash> slub -t F
stack_id:3391341428 Freed:5743 times kmem_cache:vm_area_struct size:1.75MB
   [<c02c5b00>] exit_mmap+f4
   [<c0120aa8>] __mmput+1c
   [<c0129010>] do_exit+3a8
   [<c01297e4>] do_group_exit+40
   [<c0135488>] get_signal+21c
   [<c010b2f8>] do_work_pending+16c
   [<c010106c>] slow_work_pending+c
```
### slub -T 'stack_id'
Display the slub trace by given the stack_id.
```
crash> slub -T 866893361
Pid       Freq      Size
1         424       132.50KB
282       162       50.62KB
284       153       47.81KB
322       59        18.44KB
323       96        30KB
324       93        29.06KB
325       98        30.62KB
```
## dts
This command dumps the dts info.

### dts -a
Display whole dts info.
```
crash> dts -a
/{
        model=<standalone V1.0>;
        compatible=<,xx>;
        ,msm-id=< 1e6 10000 >;
        interrupt-parent=< 1 >;
        #address-cells=< 2 >;
        #size-cells=< 2 >;
        ,board-id=< 10022 1 >;
        name=<>;

        memory{
                ddr_device_hbb_ch0_rank0=< d >;
                ddr_device_rank_ch0=< 1 >;
                ddr_device_type=< 7 >;
                device_type=<memory>;
                reg=< 0 40000000 0 3f680000 >;
                name=<memory>;
        };
```
### dts -f
Display whole dts info with address.
```
crash> dts -f
0xf7b55db8:/{
        0xf7b55e64:model=<standalone V1.0>;
        0xf7b55e90:compatible=<xx>;
        0xf7b55ebc:,msm-id=< 1e6 10000 >;
        0xf7b55ee8:interrupt-parent=< 1 >;
        0xf7b55f14:#address-cells=< 2 >;
        0xf7b55f40:#size-cells=< 2 >;
        0xf7b55f6c:,board-id=< 10022 1 >;
        0xf7b55f98:name=<>;

        0xf7b55fc8:memory{
                0xf7b56078:ddr_device_hbb_ch0_rank0=< d >;
                0xf7b560a4:ddr_device_rank_ch0=< 1 >;
                0xf7b560d0:ddr_device_type=< 7 >;
                0xf7b560fc:device_type=<memory>;
                0xf7b56128:reg=< 0 40000000 0 3f680000 >;
                0xf7b56154:name=<memory>;
        };
```

### dts -n 'node name'
Display one node info by node name or node path.
```
crash> dts -n memory
/soc/memory@045f0000
0xf7b79248:memory@045f0000{
        0xf7b79300:compatible=<,rpm-msg-ram>;
        0xf7b7932c:reg=< 45f0000 4000 >;
        0xf7b79358:phandle=< 4e >;
        0xf7b79384:name=<memory>;
};

/memory
0xf7b55fc8:memory{
        0xf7b56078:ddr_device_hbb_ch0_rank0=< d >;
        0xf7b560a4:ddr_device_rank_ch0=< 1 >;
        0xf7b560d0:ddr_device_type=< 7 >;
        0xf7b560fc:device_type=<memory>;
        0xf7b56128:reg=< 0 40000000 0 3f680000 >;
        0xf7b56154:name=<memory>;
};
```

### dts -m
Display physic memory config.
```
crash> dts -m
DDR memory ranges:
===================================================
[01]<90880000  ~  908b0000> : 192KB
[02]<908c0000  ~  908f0000> : 192KB
[03]<90c00000  ~  91a00000> : 14MB
[04]<d00000000 ~ f80000000> : 10GB
[05]<a80000000 ~ c00000000> : 6GB
[06]<900000000 ~ a80000000> : 6GB
[07]<100000000 ~ 400000000> : 12GB
[08]<d5100000  ~ 100000000> : 687MB
[09]<b0800000  ~  beb00000> : 227MB
[10]<91b00000  ~  93b00000> : 32MB
[11]<95900000  ~  95c00000> : 3MB
[12]<97a00000  ~  97b00000> : 1MB
[13]<9b700000  ~  9b800000> : 1MB
[14]<9d602000  ~  9d700000> : 1016KB
[15]<a0300000  ~  b0000000> : 253MB
===================================================
Total size:35.19GB
```

### dts -b 'file path'
Save the whole dtb memory to file.
```
crash> dts -b ./dts.dtb
dtb addr:ff8b2000, size:311582
save dtb to ./dts.dtb
```

## pageowner
This command dumps the pageowner info.

### pageowner -a
Display alloc stack for every page.
```
crash> pageowner -a
page_owner:0xffffff800737ffd8 PFN:0xbffff~0xc0000 Page:0xfffffffe01ffffc0 Order:0 stack_record:0xffffff805b9f5ad0 PID:1881 ts_nsec:78473104509
      [<ffffffd4d55b039c>] post_alloc_hook+0x20c
      [<ffffffd4d55b3064>] prep_new_page+0x28
      [<ffffffd4d55b46a4>] get_page_from_freelist+0x12ac
      [<ffffffd4d55b320c>] __alloc_pages+0xd8
      [<ffffffd4d34bfb64>] zs_malloc+0x1c8
      [<ffffffd4d37538e4>] zram_bvec_rw+0x2a8
      [<ffffffd4d375340c>] zram_rw_page.4e8b0154c58fc8baa75c3124f9a25b1c+0x9c
      [<ffffffd4d58ddba4>] bdev_write_page+0x88
      [<ffffffd4d55c21cc>] __swap_writepage+0x64
      [<ffffffd4d55c2120>] swap_writepage+0x50
      [<ffffffd4d5555dbc>] shrink_page_list+0xd18
      [<ffffffd4d5556cb0>] reclaim_pages+0x1fc
      [<ffffffd4d55c132c>] madvise_cold_or_pageout_pte_range.50c4f95024e08bb75653a011da8190a2+0x79c
      [<ffffffd4d55a4f44>] walk_pgd_range+0x324
      [<ffffffd4d55a4a34>] walk_page_range+0x1cc
      [<ffffffd4d55bfe40>] madvise_vma_behavior.50c4f95024e08bb75653a011da8190a2+0x900
```

### pageowner -f
Display free stack for every page
```
crash> pageowner -f
page_owner:0xffffff800737ffd8 PFN:0xbffff~0xc0000 Page:0xfffffffe01ffffc0 Order:0 stack_record:0xffffff805b9f5d50 PID:1881 free_ts_nsec:78470217478
      [<ffffffd4d55b11a0>] free_unref_page_prepare+0x2d8
      [<ffffffd4d55b1634>] free_unref_page_list+0xa0
      [<ffffffd4d5556528>] shrink_page_list+0x1484
      [<ffffffd4d5556cb0>] reclaim_pages+0x1fc
      [<ffffffd4d55c132c>] madvise_cold_or_pageout_pte_range.50c4f95024e08bb75653a011da8190a2+0x79c
      [<ffffffd4d55a4f44>] walk_pgd_range+0x324
      [<ffffffd4d55a4a34>] walk_page_range+0x1cc
      [<ffffffd4d55bfe40>] madvise_vma_behavior.50c4f95024e08bb75653a011da8190a2+0x900
      [<ffffffd4d55bf354>] do_madvise+0x168
      [<ffffffd4d55c015c>] __arm64_sys_process_madvise+0x150
      [<ffffffd4d52b6ad4>] invoke_syscall+0x5c
      [<ffffffd4d52b69d8>] el0_svc_common+0x94
      [<ffffffd4d52b6a6c>] do_el0_svc_compat+0x1c
      [<ffffffd4d625ec24>] el0_svc_compat+0x30
      [<ffffffd4d625ebc8>] el0t_32_sync_handler+0x60
      [<ffffffd4d5211d08>] el0t_32_sync+0x1b8
```
### pageowner -t
Display the alloc memory size for every stack.
```
Allocated 19147 times, Total memory: 74.79MB
      [<ffffffd4d55b039c>] post_alloc_hook+0x20c
      [<ffffffd4d55b3064>] prep_new_page+0x28
      [<ffffffd4d55b46a4>] get_page_from_freelist+0x12ac
      [<ffffffd4d55b320c>] __alloc_pages+0xd8
      [<ffffffd4d5549210>] page_cache_ra_unbounded+0x130
      [<ffffffd4d5549754>] do_page_cache_ra+0x3c
      [<ffffffd4d553b718>] do_sync_mmap_readahead+0x188
      [<ffffffd4d553abc0>] filemap_fault+0x280
      [<ffffffd4d5598b7c>] __do_fault+0x6c
      [<ffffffd4d5598288>] handle_pte_fault+0x1b4
      [<ffffffd4d5594820>] do_handle_mm_fault+0x4a0
      [<ffffffd4d6297488>] do_page_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x520
      [<ffffffd4d6296f50>] do_translation_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x44
      [<ffffffd4d52cbd90>] do_mem_abort+0x64
      [<ffffffd4d625ddf4>] el0_da+0x48
      [<ffffffd4d625ebe0>] el0t_32_sync_handler+0x78
      -------------------------------------------------
      PID      Comm                 Times      Size
      3867     binder:1067_18       3920       15.31MB
      712      main                 2188       8.55MB
      3791     unknow               1324       5.17MB
      2023     ndroid.systemui      1035       4.04MB
      3769     unknow               922        3.60MB
      4183     unknow               675        2.64MB
      4268     ndroid.settings      660        2.58MB
      2193     ll.splashscreen      524        2.05MB
      1067     system_server        495        1.93MB
```
### pageowner -n pfn
Display the alloc and free stack for specific pfn.
```
crash> pageowner -n 0xbfffe
page_owner:0xffffff800737ffa8 PFN:0xbfffe~0xbffff Page:0xfffffffe01ffff80 Order:0 stack_record:0xffffff8067a672c0 PID:3772 ts_nsec:118885025674
      [<ffffffd4d55b039c>] post_alloc_hook+0x20c
      [<ffffffd4d55b3064>] prep_new_page+0x28
      [<ffffffd4d55b46a4>] get_page_from_freelist+0x12ac
      [<ffffffd4d55b4a74>] __alloc_pages_slowpath+0x2a8
      [<ffffffd4d55b32b0>] __alloc_pages+0x17c
      [<ffffffd4d52cc40c>] alloc_zeroed_user_highpage_movable+0x38
      [<ffffffd4d5598568>] handle_pte_fault+0x494
      [<ffffffd4d5594820>] do_handle_mm_fault+0x4a0
      [<ffffffd4d55898cc>] __get_user_pages+0x1cc
      [<ffffffd4d5589c88>] __mm_populate+0x134
      [<ffffffd4d559b038>] do_mlock+0x240
      [<ffffffd4d559a700>] __arm64_sys_mlock+0x1c
      [<ffffffd4d52b6ad4>] invoke_syscall+0x5c
      [<ffffffd4d52b6a08>] el0_svc_common+0xc4
      [<ffffffd4d52b6a6c>] do_el0_svc_compat+0x1c
      [<ffffffd4d625ec24>] el0_svc_compat+0x30

page_owner:0xffffff800737ffa8 PFN:0xbfffe~0xbffff Page:0xfffffffe01ffff80 Order:0 stack_record:0xffffff805a538500 PID:3772 free_ts_nsec:118877743539
      [<ffffffd4d55b11a0>] free_unref_page_prepare+0x2d8
      [<ffffffd4d55b1634>] free_unref_page_list+0xa0
      [<ffffffd4d554e808>] release_pages+0x510
      [<ffffffd4d55c3988>] free_pages_and_swap_cache+0x4c
      [<ffffffd4d55a14dc>] tlb_flush_mmu+0x58
      [<ffffffd4d5590348>] unmap_page_range+0x638
      [<ffffffd4d55906b4>] unmap_vmas+0x11c
      [<ffffffd4d55a03cc>] exit_mmap+0x114
      [<ffffffd4d532f74c>] __mmput+0x38
      [<ffffffd4d532f6e4>] mmput+0x30
      [<ffffffd4d533b180>] do_exit+0x30c
      [<ffffffd4d533bc74>] do_group_exit+0x84
      [<ffffffd4d534df7c>] get_signal+0x1d8
      [<ffffffd4d52a86f0>] do_notify_resume+0x144
      [<ffffffd4d625ec5c>] el0_svc_compat+0x68
      [<ffffffd4d625ebc8>] el0t_32_sync_handler+0x60
```
### pageowner -p 'phys addr'
Display the alloc and free stack for specific physic address.
```
crash> pageowner -p 0x40001000
page_owner:0xffffff8003800038 PFN:0x40001~0x40002 Page:0xfffffffe00000040 Order:0 stack_record:0xffffff8067a672c0 PID:3772 ts_nsec:118825932080
      [<ffffffd4d55b039c>] post_alloc_hook+0x20c
      [<ffffffd4d55b3064>] prep_new_page+0x28
      [<ffffffd4d55b46a4>] get_page_from_freelist+0x12ac
      [<ffffffd4d55b4a74>] __alloc_pages_slowpath+0x2a8
      [<ffffffd4d55b32b0>] __alloc_pages+0x17c
      [<ffffffd4d52cc40c>] alloc_zeroed_user_highpage_movable+0x38
      [<ffffffd4d5598568>] handle_pte_fault+0x494
      [<ffffffd4d5594820>] do_handle_mm_fault+0x4a0
      [<ffffffd4d55898cc>] __get_user_pages+0x1cc
      [<ffffffd4d5589c88>] __mm_populate+0x134
      [<ffffffd4d559b038>] do_mlock+0x240
      [<ffffffd4d559a700>] __arm64_sys_mlock+0x1c
      [<ffffffd4d52b6ad4>] invoke_syscall+0x5c
      [<ffffffd4d52b6a08>] el0_svc_common+0xc4
      [<ffffffd4d52b6a6c>] do_el0_svc_compat+0x1c
      [<ffffffd4d625ec24>] el0_svc_compat+0x30

page_owner:0xffffff8003800038 PFN:0x40001~0x40002 Page:0xfffffffe00000040 Order:0 stack_record:0xffffff804d0bdb80 PID:3772 free_ts_nsec:118817821507
      [<ffffffd4d55b11a0>] free_unref_page_prepare+0x2d8
      [<ffffffd4d55b1634>] free_unref_page_list+0xa0
      [<ffffffd4d554e808>] release_pages+0x510
      [<ffffffd4d55c3988>] free_pages_and_swap_cache+0x4c
      [<ffffffd4d55a1678>] tlb_finish_mmu+0x8c
      [<ffffffd4d55907c0>] zap_page_range+0x104
      [<ffffffd4d55bf5fc>] madvise_vma_behavior.50c4f95024e08bb75653a011da8190a2+0xbc
      [<ffffffd4d55bf354>] do_madvise+0x168
      [<ffffffd4d55bfffc>] __arm64_sys_madvise+0x24
      [<ffffffd4d52b6ad4>] invoke_syscall+0x5c
      [<ffffffd4d52b69d8>] el0_svc_common+0x94
      [<ffffffd4d52b6a6c>] do_el0_svc_compat+0x1c
      [<ffffffd4d625ec24>] el0_svc_compat+0x30
      [<ffffffd4d625ebc8>] el0t_32_sync_handler+0x60
      [<ffffffd4d5211d08>] el0t_32_sync+0x1b8
```
### pageowner -P 'page addr'
Display the alloc and free stack for specific page address.
```
crash> pageowner -P fffffffe00000100
page_owner:0xffffff80038000c8 PFN:0x40004~0x40005 Page:0xfffffffe00000100 Order:0 stack_record:0xffffff801388e220 PID:1 ts_nsec:3217151623
      [<ffffffd4d55b039c>] post_alloc_hook+0x20c
      [<ffffffd4d55b3064>] prep_new_page+0x28
      [<ffffffd4d55b46a4>] get_page_from_freelist+0x12ac
      [<ffffffd4d55b320c>] __alloc_pages+0xd8
      [<ffffffd4d5549210>] page_cache_ra_unbounded+0x130
      [<ffffffd4d5549754>] do_page_cache_ra+0x3c
      [<ffffffd4d553b718>] do_sync_mmap_readahead+0x188
      [<ffffffd4d553abc0>] filemap_fault+0x280
      [<ffffffd4d5598b7c>] __do_fault+0x6c
      [<ffffffd4d5598288>] handle_pte_fault+0x1b4
      [<ffffffd4d5594820>] do_handle_mm_fault+0x4a0
      [<ffffffd4d6297488>] do_page_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x520
      [<ffffffd4d6296f50>] do_translation_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x44
      [<ffffffd4d52cbd90>] do_mem_abort+0x64
      [<ffffffd4d625ddf4>] el0_da+0x48
      [<ffffffd4d625ebe0>] el0t_32_sync_handler+0x78

page_owner:0xffffff80038000c8 PFN:0x40004~0x40005 Page:0xfffffffe00000100 Order:0 stack_record:0xffffff801388cd00 PID:1 free_ts_nsec:3016601310
      [<ffffffd4d55b11a0>] free_unref_page_prepare+0x2d8
      [<ffffffd4d55b1634>] free_unref_page_list+0xa0
      [<ffffffd4d554e808>] release_pages+0x510
      [<ffffffd4d554e8b8>] __pagevec_release+0x34
      [<ffffffd4d5564b54>] shmem_undo_range+0x210
      [<ffffffd4d556a9d0>] shmem_evict_inode.ac7d038029138368f3a468e11f4adc2c+0x12c
      [<ffffffd4d564152c>] evict+0xd4
      [<ffffffd4d563ed64>] iput+0x244
      [<ffffffd4d5625f1c>] do_unlinkat+0x1ac
      [<ffffffd4d562605c>] __arm64_sys_unlinkat+0x48
      [<ffffffd4d52b6ad4>] invoke_syscall+0x5c
      [<ffffffd4d52b6a08>] el0_svc_common+0xc4
      [<ffffffd4d52b6a6c>] do_el0_svc_compat+0x1c
      [<ffffffd4d625ec24>] el0_svc_compat+0x30
      [<ffffffd4d625ebc8>] el0t_32_sync_handler+0x60
      [<ffffffd4d5211d08>] el0t_32_sync+0x1b8
```
### pageowner -m
Display the alloc memory size for every process.
```
crash> pageowner -m
PID      Comm                 Times      Size
         page_owner                      20.80MB
         stack_record                    16KB
3772     memtester            179573     701.46MB
1        init                 19078      104.62MB
712      main                 14640      58.88MB
1881     CachedAppOptimi      13552      52.98MB
68       kswapd0              11550      45.20MB
960      unknow               8262       32.44MB
4268     ndroid.settings      6485       25.36MB
```
## rtb
This command is used to view detailed information about rtb log.

### rtb -a
Display all rtb log.
```
crash> rtb -a
[234.501572] [12532244321] <0>: LOGK_CTXID ctxid:4284 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501602] [12532244897] <0>: LOGK_IRQ interrupt:1 handled from addr ffffffd4d627c7b4 ipi_handler.04f2cb5359f849bb5e8105832b6bf932.cfi_jt Line 888 of "arch/arm64/ke            rnel/entry.S"
[234.501628] [12532245392] <0>: LOGK_CTXID ctxid:943 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501799] [12532248689] <0>: LOGK_CTXID ctxid:4284 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501829] [12532249254] <0>: LOGK_CTXID ctxid:1621 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501836] [12532249398] <0>: LOGK_IRQ interrupt:1 handled from addr ffffffd4d627c7b4 ipi_handler.04f2cb5359f849bb5e8105832b6bf932.cfi_jt Line 888 of "arch/arm64/ke            rnel/entry.S"
```

## wdt
This command is used to view watchdog info.

### wdt -a
Display watchdog info.
```
crash> wdt -a
enabled               : True
wdt_base              : c5a66000
user_pet_enabled      : False
pet_time              : 9.36s
bark_time             : 15s
bite_time             : 18s
bark_irq              : 25
user_pet_complete     : True
wakeup_irq_enable     : True
in_panic              : True
irq_ppi               : False
freeze_in_progress    : False

pet_timer:
  jiffies             : 4299314482
  expires             : 4348153
  timer_expired       : False
  timer_fired         : 14784480161054
  last_jiffies_update : 14790618520938
  tick_next_period    : 14790621854271
  tick_do_timer_cpu   : 3

watchdog_thread:
  watchdog_task       : eb1d5c80
  pid                 : 40
  cpu                 : 0
  task_state          : IN
  last_run            : 14784480389231
  thread_start        : 14784480630012
  last_pet            : 14784480640950
  do_ipi_ping         : True
  ping cpu[0]         : 1203198795~1203203274(4479ns)
  ping cpu[1]         : 0~0(0ns)
  ping cpu[2]         : 0~0(0ns)
  ping cpu[3]         : 0~0(0ns)

```

### rtb -c 'cpu'
Display rtb log with cpu.
```
crash> rtb -c 0
[234.501572] [12532244321] <0>: LOGK_CTXID ctxid:4284 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501602] [12532244897] <0>: LOGK_IRQ interrupt:1 handled from addr ffffffd4d627c7b4 ipi_handler.04f2cb5359f849bb5e8105832b6bf932.cfi_jt Line 888 of "arch/arm64/ke            rnel/entry.S"
[234.501628] [12532245392] <0>: LOGK_CTXID ctxid:943 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501799] [12532248689] <0>: LOGK_CTXID ctxid:4284 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501829] [12532249254] <0>: LOGK_CTXID ctxid:1621 called from addr ffffffd4d628a684 __schedule Line 220 of "include/trace/events/sched.h"
[234.501836] [12532249398] <0>: LOGK_IRQ interrupt:1 handled from addr ffffffd4d627c7b4 ipi_handler.04f2cb5359f849bb5e8105832b6bf932.cfi_jt Line 888 of "arch/arm64/ke            rnel/entry.S"
```
## wq
This command dumps the workqueue info.

### wq -w
Display all worker.
```
crash> wq -w
worker           name          pid    flags                                  workqueue       sleeping last_active IDLE last_func                                                          current_func
ffffff8017efbe40 kworker/u8:4  385    WORKER_PREP|WORKER_IDLE|WORKER_UNBOUND memlat_wq       0        4294951343  Yes  memlat_update_work.ced2387b2ffe06d71748357bedbe93a2.cfi_jt+0x0     None
ffffff8016d1e180 kworker/u8:3  362    WORKER_PREP|WORKER_IDLE|WORKER_UNBOUND adb             0        4294951343  Yes  ffs_user_copy_worker.b0cd75eaae5d58bcb6aaf6fa4f4857ee.cfi_jt+0x0   None
ffffff80083d9c00 kworker/2:1H  109    WORKER_PREP|WORKER_IDLE                kverityd        0        4294951341  Yes  verity_prefetch_io.bb921613a07c200788484c1e05cde4c1.cfi_jt+0x0     None
ffffff80697d3780 kworker/1:6H  3888   WORKER_PREP|WORKER_IDLE                kverityd        0        4294951341  Yes  verity_work.bb921613a07c200788484c1e05cde4c1.cfi_jt+0x0            None
ffffff8016f0b300 kworker/1:4   541    WORKER_PREP|WORKER_IDLE                events          0        4294951331  Yes  handle_update.f3ba35adcfc3b8df74da779354a74767.cfi_jt+0x0          None
ffffff80143c7a80 kworker/0:7   439    WORKER_PREP|WORKER_IDLE                pm              0        4294951325  Yes  pm_runtime_work.e82816fbe6e30b4c36613b999953c187.cfi_jt+0x0        None
ffffff801d246540 kworker/0:4H  1081   WORKER_PREP|WORKER_IDLE                kverityd        0        4294951320  Yes  verity_prefetch_io.bb921613a07c200788484c1e05cde4c1.cfi_jt+0x0     None
ffffff80194e7300 kworker/2:3   451    WORKER_PREP|WORKER_IDLE                mm_percpu_wq    0        4294951256  Yes  vmstat_update.e559268912d9db5a285c4a36ab11201a.cfi_jt+0x0          None
ffffff8013cad9c0 kworker/3:3   367    WORKER_PREP|WORKER_IDLE                mm_percpu_wq    0        4294951248  Yes  vmstat_update.e559268912d9db5a285c4a36ab11201a.cfi_jt+0x0          None
```
### wq -p
Display worker_pool.
```
crash> wq -p
worker_pool           cpu        workers    idle       running    works      flags
ffffff800301a400      Unbound    8          8          0          0          POOL_DISASSOCIATED
ffffff806d1b8580      1          15         15         0          0          None
ffffff806d1d6580      2          3          3          0          0          None
ffffff806d1f4580      3          3          3          0          0          None
```

### wq -P 'worker_pool addr'
Display worker by given the worker_pool address.
```
crash> wq -P ffffff800301a400
worker:
   kworker/u8:0 [Idle] pid:8
   kworker/u8:1 [Idle] pid:10
   kworker/u8:2 [Idle] pid:67
   kworker/u8:3 [Idle] pid:362
   kworker/u8:4 [Idle] pid:385
   kworker/u8:5 [Idle] pid:944
   kworker/u8:6 [Idle] pid:1530
   kworker/u8:7 [Idle] pid:1589

Delayed Work:

Pending Work:
```

## df
This command dumps the mount info.

### df -s
```
crash> df -s
Partition                      Type  Blocks     Block SZ   Size       Used       Avail      Use%
/system_dlkm                   ext4  3043       4KB        11.89MB    11.85MB    40KB       99.67%
/vendor/dsp                    ext4  15093      4KB        58.96MB    8.04MB     50.92MB    13.64%
/product                       ext4  46313      4KB        180.91MB   180.37MB   556KB      99.70%
/vendor                        ext4  81110      4KB        316.84MB   315.85MB   1012KB     99.69%
/                              ext4  186571     4KB        728.79MB   726.56MB   2.23MB     99.69%
/mnt/pass_through/0/emulated   f2fs  1834496    4KB        7.00GB     250.70MB   6.75GB     3.50%
/vendor_dlkm                   ext4  15286      4KB        59.71MB    59.53MB    184KB      99.70%
/mnt/vendor/persist            ext4  6908       4KB        26.98MB    908KB      26.10MB    3.29%
/metadata                      f2fs  15872      4KB        62MB       34.14MB    27.86MB    55.07%
/system_ext                    ext4  99458      4KB        388.51MB   387.33MB   1.18MB     99.70%
```
## binder
This command dumps the binder information.

### binder -a
Display all binder proc states.
```
crash> binder -a
binder_proc:0xffffff801a7a5400 ndroid.settings [4268] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:4 requested:0 started:2 ready:3
  binder_thread:0xffffff80543a5800 pid:4283 loop:18 need_return:0
  binder_thread:0xffffff802b9dbe00 pid:4268 loop:16 need_return:0
    outgoing transaction:0xffffff8068d7fa00 id:98800 from 4268:4268 to 504:504 code:7 flags:16 pri:SCHED_NORMAL[110] reply:1
  binder_thread:0xffffff8053816c00 pid:4284 loop:17 need_return:0
  binder_thread:0xffffff8062513400 pid:4285 loop:17 need_return:0
  binder_node:0xffffff8014417c00 id:98764 ptr:0xf1b053a0 cookie:0xefb79838 pri:SCHED_NORMAL[139] hs:1 hw:1 ls:0 lw:0 is:1 iw:1 tr:0
     binder_ref:0xffffff8066bd9600 id:98765 binder_proc:0xffffff8016b5ac00 system_server[1067]
```
### binder -p 'pid'
Display specific process binder states.
```
crash> binder -p 1067
binder_proc:0xffffff8017fd9400 system_server [1067] hwbinder dead:0 frozen:0 sr:0 ar:0 max:4 total:12 requested:0 started:4 ready:5
  binder_thread:0xffffff804d132000 pid:2046 loop:0 need_return:0
  binder_thread:0xffffff8058c4b600 pid:2103 loop:17 need_return:0
  binder_thread:0xffffff805c4aa400 pid:2619 loop:0 need_return:0
  binder_node:0xffffff8056dbc780 id:4259 ptr:0xe28965f0 cookie:0xe289c000 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:1 tr:0
     binder_ref:0xffffff8056ec2280 id:4260 binder_proc:0xffffff80155e0c00 powerstateservi[588]
  binder_node:0xffffff805a50cf00 id:11867 ptr:0xed6eff10 cookie:0xde8d6150 pri:SCHED_NORMAL[120] hs:1 hw:1 ls:0 lw:0 is:1 iw:1 tr:0
     binder_ref:0xffffff8056f18080 id:11868 binder_proc:0xffffff8017652800 mediaswcodec[1184]
  binder_ref:0xffffff8027197a80 id:11301 desc:7 s:1 w:1 death:0 -> node_id:1423 binder_proc:0xffffff801436f000 vendor.qti.medi[908]
  binder_ref:0xffffff8053718c80 id:4199 desc:3 s:1 w:1 death:0xffffff8054f70540 -> node_id:1821 binder_proc:0xffffff8017de8c00 aonutility@1.0-[884]
  binder_ref:0xffffff8053718900 id:4152 desc:1 s:0 w:1 death:0 -> node_id:4151 binder_proc:0xffffff8016ba6c00 hwservicemanage[509]
```
### binder -l
Display binder transaction log.
```
crash> binder -l
98799 : reply from 1067:4161 to 4268:4268 context binder node 0 handle -1 size 1716:0 ret 0/0 l=0
98800 : call  from 4268:4268 to 504:0 context binder node 1 handle 0 size 156:0 ret 0/0 l=0
98737 : reply from 1067:4161 to 4268:4268 context binder node 0 handle -1 size 1716:0 ret 0/0 l=0
98738 : call  from 4268:4268 to 504:0 context binder node 1 handle 0 size 88:0 ret 0/0 l=0
98739 : reply from 504:504 to 4268:4268 context binder node 0 handle -1 size 32:8 ret 0/0 l=0
98741 : call  from 4268:4268 to 1067:0 context binder node 10747 handle 26 size 132:0 ret 0/0 l=0
98742 : reply from 1067:4161 to 4268:4268 context binder node 0 handle -1 size 8:0 ret 0/0 l=0
```

### binder -f
Display binder fail log.
```
crash> binder -f
45546 : call  from 3182:3182 to 0:0 context binder node 1066 handle 25 size 0:0 ret 29201/-1 l=3273
45551 : call  from 3182:3182 to 0:0 context binder node 1066 handle 25 size 0:0 ret 29201/-1 l=3273
58748 : call  from 3431:3431 to 0:0 context binder node 1066 handle 25 size 0:0 ret 29201/-1 l=3273
58753 : call  from 3431:3431 to 0:0 context binder node 1066 handle 25 size 0:0 ret 29201/-1 l=3273
68878 : async from 1067:1067 to 0:0 context binder node 0 handle 584 size 124:0 ret 29189/-22 l=3258
69422 : async from 1067:1067 to 0:0 context binder node 0 handle 588 size 124:0 ret 29189/-22 l=3258
77204 : async from 1067:2998 to 3719:0 context binder node 73053 handle 1017 size 84:0 ret 29189/-3 l=3445
```

### binder -n
Display binder node info.
```
crash> binder -n
binder_proc:0xffffff801a7a5400 ndroid.settings [4268] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:4 requested:0 started:2 ready:3
  binder_node:0xffffff8014417c00 id:98764 ptr:0xf1b053a0 cookie:0xefb79838 pri:SCHED_NORMAL[139] hs:1 hw:1 ls:0 lw:0 is:1 iw:1 tr:0
     binder_ref:0xffffff8066bd9600 id:98765 binder_proc:0xffffff8016b5ac00 system_server[1067]
  binder_node:0xffffff8053beea80 id:98727 ptr:0xf1b05240 cookie:0xefb797e8 pri:SCHED_NORMAL[139] hs:1 hw:1 ls:0 lw:0 is:1 iw:1 tr:0
     binder_ref:0xffffff80654e9980 id:98728 binder_proc:0xffffff8016b58400 perfservice[1130]
```

### binder -b
Display binder buffer info.
```
binder_proc:0xea194000 viders.calendar [7340] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:6 requested:0 started:4 ready:5
  binder_alloc:0xea194154 mm_struct:0xe681df80 vma:0xefa9d880 buffer:0x81a39000 size:1040384 free:520192
    Page :0xf815f28c PA:0xa664b000
    Page :0xf7d338f8 PA:0x88bce000
    Free binder_buffer :0xdb035300 id:409018 data:0x81a390e0 PA:0xa664b0e0 size:296 offset:24 extra:0 pid:666 delivered
    Alloc binder_buffer:0xdd8f62c0 id:408034 data:0x81a390d8 PA:0xa664b0d8 size:8 offset:0 extra:0 pid:1239 delivered

```

### binder -t
Display binder thread info.
```
crash> binder -t
binder_proc:0xffffff801a7a5400 ndroid.settings [4268] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:4 requested:0 started:2 ready:3
  binder_thread:0xffffff80543a5800 pid:4283 loop:18 need_return:0
  binder_thread:0xffffff802b9dbe00 pid:4268 loop:16 need_return:0
    outgoing transaction:0xffffff8068d7fa00 id:98800 from 4268:4268 to 504:504 code:7 flags:16 pri:SCHED_NORMAL[110] reply:1
  binder_thread:0xffffff8053816c00 pid:4284 loop:17 need_return:0
  binder_thread:0xffffff8062513400 pid:4285 loop:17 need_return:0
```
### binder -r
Display binder ref info.
```
crash> binder -r
binder_proc:0xffffff801a7a5400 ndroid.settings [4268] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:4 requested:0 started:2 ready:3
  binder_ref:0xffffff80538f2000 id:97816 desc:7 s:1 w:1 death:0 -> node_id:7509 binder_proc:0xffffff8016b5ac00 system_server[1067]
  binder_ref:0xffffff80538f2880 id:97812 desc:3 s:1 w:1 death:0 -> node_id:4008 binder_proc:0xffffff8016b5ac00 system_server[1067]
  binder_ref:0xffffff805b026d00 id:97775 desc:1 s:1 w:1 death:0 -> node_id:5632 binder_proc:0xffffff8016b5ac00 system_server[1067]
  binder_ref:0xffffff805d210600 id:97772 desc:0 s:1 w:1 death:0 -> node_id:1 binder_proc:0xffffff801f8d6400 servicemanager[504]
  binder_ref:0xffffff80538f2480 id:97811 desc:2 s:1 w:1 death:0 -> node_id:4401 binder_proc:0xffffff8016b5ac00 system_server[1067]
```

## cpu
This command dumps the cpu info.

### cpu -p
Display cpu freq policy.
```
crash> cpu -p
CPU cpufreq_policy       cluster cur_freq   min_freq   max_freq   governor
0   e565fa00             0       1708800    1708800    1708800    schedutil
1   e565fa00             0       1708800    1708800    1708800    schedutil
2   e565fa00             0       1708800    1708800    1708800    schedutil
3   e565fa00             0       1708800    1708800    1708800    schedutil
```
### cpu -f
Display cpu freq table.
```
crash> cpu -f
CPU0            CPU1            CPU2            CPU3
614400          614400          614400          614400
864000          864000          864000          864000
1363200         1363200         1363200         1363200
1708800         1708800         1708800         1708800
```
## tm
This command dumps the thermal info.

### tm -d
Display all thermal zone info.
```
crash> tm -d
ID    ADDR       Name               governor     cur_temp   last_temp
0     e9ad0400   pm5100-tz          step_wise    32086      32120
1     e9ad2800   pm5100-ibat-lvl0   step_wise    31         31
2     e9ad5800   pm5100-ibat-lvl1   step_wise    31         31
3     e9ad7000   pm5100-bcl-lvl0    step_wise    0          0
4     e9ae2800   pm5100-bcl-lvl1    step_wise    0          0
5     e9ae7000   pm5100-bcl-lvl2    step_wise    0          0
```
### tm -D
Display the temperature gear and cooling action of specified thermal zone.
```
crash> tm -D pm5100-tz
pm5100-tz:
   temperature:95000
      [3]thermal_cooling_device:0xe574e400 --> thermal-cpufreq-0
      [6]thermal_cooling_device:0xe574a800 --> cpu-isolate2
      [7]thermal_cooling_device:0xe574d800 --> cpu-isolate3
   temperature:115000
   temperature:145000
```
## dd
This command dumps the device driver info.

### dd -b
Display all bus info.
```
crash> dd -b
bus_type   name         subsys_private   probe func
c1c8dcd0   platform     eb1e0e00
c1c8dd88   cpu          eb1e0200
c1c8e068   container    eb1e1a00
c1c171b0   workqueue    eb1e6200
c1c543b8   gpio         eb1e5c00
c1c8e710   genpd        eb1e7400
c1c8f108   soc          eb1e7a00
c1c549c0   pci          ea0f0e00         pci_device_probe+0
```
### dd -B 'bus name'
Display all device and driver info for specified bus.
```
crash> dd -B platform
============================================================================
                                All devices
============================================================================
device     name                                                              driver     driver_name
ea0b4c10   reg-dummy                                                         c1c67ba8   reg-dummy
e9c1cc10   c600000.apps-smmu                                                 c1c7fc70   arm-smmu
============================================================================
                                All drivers
============================================================================
device_driver    name                            compatible                      probe func
c1ca4b50         bluesleep                       bcm,bluesleep                   platform_drv_probe+0
c1ca6110         lpm-levels                      ,lpm-levels                 platform_drv_probe+0
c1ca6f48         pwrseq_simple                   mmc-pwrseq-simple               platform_drv_probe+0
```
### dd -c
Display all class info.
```
crash> dd -c
class      name                 subsys_private
c1c678d0   regulator            eb1e0800
ea0d6680   bdi                  ea0f3800
c1c54478   gpio                 ea0f5000
c1c54850   pci_bus              ea0f6800
ea0d7680   backlight            ea0f4400
```
### dd -C 'class name'
Display all device info for specified class.
```
crash> dd -C backlight
============================================================================
                                All devices
============================================================================
device     name             driver     driver_name
e3174c60   panel0-backlight

```
### dd -d
Display all device info.
```
crash> dd -d
device     name                                                              Bus             driver     driver_name
ea0b4c10   reg-dummy                                                         platform        c1c67ba8   reg-dummy
ea112810   soc                                                               platform
ea110410   soc:psci                                                          platform
```
### dd -D
Display all driver info.
```
crash> dd -D
device_driver    name                                     Bus             compatible                      probe func
c1ca6f48         pwrseq_simple                            platform        mmc-pwrseq-simple               platform_drv_probe+0
c1ca6fd8         pwrseq_emmc                              platform        mmc-pwrseq-emmc                 platform_drv_probe+0
```
### dd -s
Display all device for specified driver.
```
crash> dd -s rpm-smd-regulator-resource
   device     name
   e9b44c10   soc:rpm-smd:rpm-regulator-smpa1
   e9001010   soc:rpm-smd:rpm-regulator-smpa3
   e9006410   soc:rpm-smd:rpm-regulator-smpa4
```
## getprop
This command dumps the property info.

### getprop -s 'symbol path'
Load symbol for property，you must insmod the zram ko before run this command.
```
crash> mod -s zram ./lib/zram.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d3758440  zram                       ffffffd4d3752000     49152  ./lib/zram.ko

crash> mod -s zsmalloc ./lib/zsmalloc.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d34c6200  zsmalloc                   ffffffd4d34bf000     57344  ./lib/zsmalloc.ko

crash> getprop -s xxx/symbols
add symbol table from file "xxx/symbols/system/lib/bootstrap/libc.so"
Reading symbols from xxx/symbols/system/lib/bootstrap/libc.so...
Add symbol:xxx/symbols/system/lib/bootstrap/libc.so succ
```
### getprop -a
Display all propertys.
```
crash> getprop -a
[0001]persist.sys.timezone                                 GMT
[0006]dev.mnt.dev.data_mirror.ref_profiles                 dm-12
[0007]dev.mnt.dev.data_mirror.cur_profiles                 dm-12
[0008]dev.mnt.dev.system_dlkm                              dm-11
[0009]dev.mnt.dev.vendor_dlkm                              dm-10
[0010]dev.mnt.dev.vendor.bt_firmware                       mmcblk0p30
```
### getprop -p 'prop name'
Display specified property's value.
```
crash> getprop -p dev.mnt.dev.vendor.bt_firmware
mmcblk0p30
```
## logcat
This command dumps the logcat log info.

### logcat -s 'symbol path'
Load symbol for logd. you must insmod the zram ko before run this command.
```
crash> mod -s zram ./lib/zram.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d3758440  zram                       ffffffd4d3752000     49152  ./lib/zram.ko

crash> mod -s zsmalloc ./lib/zsmalloc.ko
     MODULE       NAME                             BASE            SIZE  OBJECT FILE
ffffffd4d34c6200  zsmalloc                   ffffffd4d34bf000     57344  ./lib/zsmalloc.ko

crash> logcat -s xxx/symbols
add symbol table from file "xxx/symbols/system/lib/bootstrap/libc.so"
Reading symbols from xxx/symbols/system/lib/bootstrap/libc.so...
Add symbol:xxx/symbols/system/lib/bootstrap/libc.so succ
add symbol table from file "xxx/symbols/system/bin/logd"
Reading symbols from xxx/symbols/system/bin/logd...
Add symbol:xxx/symbols/system/bin/logd succ
```
###  logcat -b 'log id'
Display all logcat log.
```
crash> logcat -b all
android_version is : 34 !
06-25 18:58:59.000534 499   499   1069   D lowmemorykiller Zone Normal: free:0 high:0 cma:0 reserve:(0 0 0) anon:(0 0) file:(0 0)
06-25 18:58:59.000534 499   499   1069   D lowmemorykiller Zone Movable: free:0 high:0 cma:0 reserve:(0 0 0) anon:(0 0) file:(0 0)
06-25 18:58:59.000534 499   499   1069   I lowmemorykiller Ignoring pressure since per-zone watermarks ok
06-25 18:58:59.000547 499   499   1069   I lowmemorykiller super critical memory pressure event is triggered
```
Display main log.
```
crash> logcat -b main
android_version is : 34 !
06-25 18:58:59.000534 499   499   1069   D lowmemorykiller Zone Normal: free:0 high:0 cma:0 reserve:(0 0 0) anon:(0 0) file:(0 0)
06-25 18:58:59.000534 499   499   1069   D lowmemorykiller Zone Movable: free:0 high:0 cma:0 reserve:(0 0 0) anon:(0 0) file:(0 0)
06-25 18:58:59.000534 499   499   1069   I lowmemorykiller Ignoring pressure since per-zone watermarks ok
06-25 18:58:59.000547 499   499   1069   I lowmemorykiller super critical memory pressure event is triggered
```
Display system log.
```
crash> logcat -b system
06-25 18:56:37.000327 1067  3459  1000   I ActivityManager Process android.process.acore (pid 2783) has died: prev LAST
06-25 18:56:37.000329 1067  2066  1000   D CountryDetector No listener is left
06-25 18:56:37.000338 1067  1634  1000   D DisplayManagerService Drop pending events for gone uid 10033
06-25 18:56:37.000893 1067  3459  1000   I ActivityManager Process android.process.media (pid 3002) has died: prev LAST
06-25 18:56:37.000898 1067  1634  1000   D DisplayManagerService Drop pending events for gone uid 10030
06-25 18:56:38.000342 2023  3579  10100  D PowerUI can't show warning due to - plugged: true status unknown: false
06-25 18:56:38.000346 2023  3580  10100  D PowerUI can't show warning due to - plugged: true status unknown: false
```
Display radio log.
```
crash> logcat -b radio
01-01 08:07:24.000061 839   894   1021   D RilApiSession [RilApiSession.cpp: 139] [Loc_hal_worker(839,894)] initialize: Initializing RIL API session.
01-01 08:07:24.000081 839   894   1021   D RilApiSession [RilApiSession.cpp: 52] [Loc_hal_worker(839,894)] createUnixSocket: Failed to connect to the server. Error: No such file or directory
01-01 08:07:26.000084 839   894   1021   D RilApiSession [RilApiSession.cpp: 139] [Loc_hal_worker(839,894)] initialize: Initializing RIL API session.
01-01 08:07:26.000084 839   894   1021   D RilApiSession [RilApiSession.cpp: 52] [Loc_hal_worker(839,894)] createUnixSocket: Failed to connect to the server. Error: No such file or directory
01-01 08:07:28.000085 839   894   1021   D RilApiSession [RilApiSession.cpp: 139] [Loc_hal_worker(839,894)] initialize: Initializing RIL API session.
01-01 08:07:28.000085 839   894   1021   D RilApiSession [RilApiSession.cpp: 52] [Loc_hal_worker(839,894)] createUnixSocket: Failed to connect to the server. Error: No such file or directory
01-01 08:07:31.000504 1065  1065  1001   D RILD **RIL Daemon Started**
01-01 08:07:31.000509 1065  1065  1001   D RILD **RILd param count=1**
```
Display event log.
```
crash> logcat -b events
01-01 08:07:10.000236 504   504   1000   I :[121035042,-1,]
01-01 08:07:10.000256 504   504   1000   I :[Multiple same specifications for vendor.qti.gnss.ILocAidlGnss/default.]
01-01 08:07:10.000256 504   504   1000   I :[Multiple same specifications for vendor.qti.hardware.qteeconnector.IAppConnector/default.]
01-01 08:07:10.000256 504   504   1000   I :[Multiple same specifications for vendor.qti.hardware.qteeconnector.IGPAppConnector/default.]
01-01 08:07:10.000259 504   504   1000   I :[SELinux: Loaded service context from:]
01-01 08:07:10.000259 504   504   1000   I :[           /system/etc/selinux/plat_service_contexts]
01-01 08:07:10.000259 504   504   1000   I :[           /system_ext/etc/selinux/system_ext_service_contexts]
01-01 08:07:10.000259 504   504   1000   I :[           /product/etc/selinux/product_service_contexts]
01-01 08:07:10.000259 504   504   1000   I :[           /vendor/etc/selinux/vendor_service_contexts]
01-01 08:07:10.000413 512   512   1000   I :[121035042,-1,]
01-01 08:00:00.000160 487   487   1036   I :[type=2000 audit(0.0:1): state=initialized audit_enabled=0 res=1]
01-01 08:07:02.000011 487   487   1036   I :[type=1403 audit(0.0:2): auid=4294967295 ses=4294967295 lsm=selinux res=1]
```
Display crash log.
```
crash> logcat -b crash
06-25 18:56:18.000253 3098  3098  10137  E AndroidRuntime FATAL EXCEPTION: main
Process: com.android.devicelockcontroller, PID: 3098
java.lang.ExceptionInInitializerError
        at com.android.devicelockcontroller.SystemDeviceLockManagerImpl.getInstance(SystemDeviceLockManagerImpl.java:68)
        at com.android.devicelockcontroller.policy.DevicePolicyControllerImpl.<init>(DevicePolicyControllerImpl.java:103)
        at com.android.devicelockcontroller.policy.DevicePolicyControllerImpl.<init>(DevicePolicyControllerImpl.java:89)
        at com.android.devicelockcontroller.DeviceLockControllerApplication.getPolicyController(DeviceLockControllerApplication.java:81)
        at com.android.devicelockcontroller.DeviceLockControllerApplication.getStateController(DeviceLockControllerApplication.java:74)
        at com.android.devicelockcontroller.DeviceLockControllerApplication.onCreate(DeviceLockControllerApplication.java:67)
        at android.app.Instrumentation.callApplicationOnCreate(Instrumentation.java:1317)
        at android.app.ActivityThread.handleBindApplication(ActivityThread.java:7017)
        at android.app.ActivityThread.-$$Nest$mhandleBindApplication(Unknown Source:0)
        at android.app.ActivityThread$H.handleMessage(ActivityThread.java:2237)
        at android.os.Handler.dispatchMessage(Handler.java:106)
        at android.os.Looper.loopOnce(Looper.java:205)
        at android.os.Looper.loop(Looper.java:294)
        at android.app.ActivityThread.main(ActivityThread.java:8223)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:552)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:977)
Caused by: java.lang.NullPointerException: Attempt to invoke virtual method 'android.devicelock.IDeviceLockService android.devicelock.DeviceLockManager.getService()' on a null object reference
        at com.android.devicelockcontroller.SystemDeviceLockManagerImpl.<init>(SystemDeviceLockManagerImpl.java:51)
        at com.android.devicelockcontroller.SystemDeviceLockManagerImpl.<init>(SystemDeviceLockManagerImpl.java:55)
        at com.android.devicelockcontroller.SystemDeviceLockManagerImpl.<init>(SystemDeviceLockManagerImpl.java:0)
        at com.android.devicelockcontroller.SystemDeviceLockManagerImpl$SystemDeviceLockManagerHolder.<clinit>(SystemDeviceLockManagerImpl.java:60)
        ... 17 more
```
## coredump
This command generate process coredump.

### coredump -p 'pid'
Generate process coredump.
```
crash> coredump -p 323
```

### coredump -p 'pid' -s 'symbols_path' -f
Generate process fake coredump with symbols.
```
overwrite /system/bin/logd:[size:0x15000 off:0] to core:[0x6052e20000 - 0x6052e35000]
```

### coredump -p 'pid' -s 'symbols_path' -r
```
overwrite PHDR /system/bin/logd:[size:0x15000 off:0] to core:[0x6052e20000 - 0x6052e35000]
```

### coredump -l 'pid' -s 'symbols_path'
get the linkmap with symbols
```
addr                ld                  next                prev                name
56ef6c4000          56ef6cc090          7eafbb4158          0                   /system/bin/app_process64
7eafa2a000          7eafb9f3b8          7eae8eb388          7eae8eb0e0          /system/bin/linker64
7eafa29000          7eafa29848          7eae8eb630          7eafbb4158          [vdso]
```

### coredump -m 'pid'
Show process maps.
```
crash> coredump -m 437
VMA:ffffff801d653b40 [6052e20000-6052e35000] r--p 0000000000000071 00000000 /system/bin/logd
VMA:ffffff801d653000 [6052e38000-6052ebd000] r-xp 0000000000000075 00000018 /system/bin/logd
VMA:ffffff80279c05a0 [7befacb000-7befb14000] rw-p 0000000000100073 07befacb [anon:scudo:secondary]
```

## tm
This command dumps the thermal info.

### tm -d
Display all thermal zone info.
```
crash> tm -d
ID    ADDR       Name               governor     cur_temp   last_temp
0     e9ad0400   pm5100-tz          step_wise    32086      32120
1     e9ad2800   pm5100-ibat-lvl0   step_wise    31         31
2     e9ad5800   pm5100-ibat-lvl1   step_wise    31         31
3     e9ad7000   pm5100-bcl-lvl0    step_wise    0          0
4     e9ae2800   pm5100-bcl-lvl1    step_wise    0          0
5     e9ae7000   pm5100-bcl-lvl2    step_wise    0          0
```
### tm -D 'zone name'
Display the temperature gear and cooling action of specified thermal zone.
```
crash> tm -D pm5100-tz
pm5100-tz:
   temperature:95000
      [0]thermal_cooling_device:0xffffff8009240800 --> cpufreq-cpu0
      [7]thermal_cooling_device:0xffffff801e78d800 --> thermal-pause-4
      [9]thermal_cooling_device:0xffffff801eafc800 --> thermal-pause-8
   temperature:115000
   temperature:145000
```

## cache
This command dumps the page cache info.

### cache -f
Display all file info.
```
crash> cache -f
Total File cache size: 704.48MB
===============================================
inode            address_space    nrpages  size       Path
ffffff8030288f68 ffffff8030289130 8901     34.77MB    /system/framework/framework.jar
ffffff80546f3178 ffffff80546f3340 8747     34.17MB    /priv-app/Settings/Settings.apk
ffffff8035864cb8 ffffff8035864e80 5312     20.75MB    /system/framework/services.jar
```

### cache -a
Display all anon pages.
```
crash> cache -a
page:0xfffffffe00000000  paddr:0x40000000
page:0xfffffffe00000040  paddr:0x40001000
page:0xfffffffe00000080  paddr:0x40002000
page:0xfffffffe000000c0  paddr:0x40003000
```

## dbi
This command dumps the debug image info.

### dbi -a
Display all debug image.
```
crash> dbi -a
DumpTable base:bc700000
Id   Dump_entry       version  magic            DataAddr         DataLen    Name
0    bc707e10         20       42445953         bc707e50         2048       c0_context
1    bc708650         20       42445953         bc708690         2048       c1_context
2    bc708e90         20       42445953         bc708ed0         2048       c2_context
3    bc7096d0         20       42445953         bc709710         2048       c3_context
96   bc709f10         20       42445953         bc709f50         36928      l1_icache0
97   bc712f90         20       42445953         bc712fd0         36928      l1_icache1
98   bc71c010         20       42445953         bc71c050         36928      l1_icache2
```

Generate the cmm file.
```
crash> dbi -c
c0_context  core:0  version:1.4
c1_context  core:1  version:1.4
c2_context  core:2  version:1.4
c3_context  core:3  version:1.4
```

Parser specified cpu stack(skip swapper).
```
vm_3_vcpu_400  core:4  version:2.0
Core4 PC: <ffffffc080033080>: local_cpu_stop+20
Core4 LR: <ffffffc080033074>: local_cpu_stop+14
PID: 0        TASK: ffffff88005213c0  CPU: 4    COMMAND: "swapper/4"
 #0 [ffffffc08259bf60] ipi_handler at ffffffc08003313c
 #1 [ffffffc08259bf90] handle_percpu_devid_irq at ffffffc080182e4c
 #2 [ffffffc08259bfd0] generic_handle_domain_irq at ffffffc08017b534
 #3 [ffffffc08259bfe0] gic_handle_irq at ffffffc08001012c
--- <IRQ stack> ---
 #4 [ffffffc082743bc0] call_on_irq_stack at ffffffc08001f1bc
 #5 [ffffffc082743bd0] exit_to_kernel_mode at ffffffc0811251a0
 #6 [ffffffc082743bf0] el1_interrupt at ffffffc081124394
 #7 [ffffffff82743c10] __kvm_nvhe___kcfi_typeid_hyp_unpin_shared_mem at ffffffa630d39ffc
```

unwind specified pid stack(only support ARM64).
```
crash> dbi -p 141
cpu_context:
   X19: 0xffffff8800523b40
   X20: 0xffffff8803cea780
   X21: 0xffffff8803cea780
   X22: 0
   X23: 0x402
   X24: 0xffffff8800523b40
   X25: 0x2
   X26: 0x1
   X27: 0xffffff8803cea780
   X28: 0
   fp:  0xffffffc083c0bd00
   sp:  0xffffffc083c0bd00
   pc:  0xffffffc081128a94

Stack:0xffffffc083c08000~0xffffffc083c0c000
[0]Potential backtrace -> FP:0xffffffc083c0bb80, LR:0xffffffc083c0bb88
 #0 [ffffffc083c0bba0] hrtimer_try_to_cancel at ffffffc0801c8060
 #1 [ffffffc083c0bbe0] dl_server_stop at ffffffc080133ca4
 #2 [ffffffc083c0bc40] dequeue_entities at ffffffc080123690
 #3 [ffffffc083c0bc80] psi_group_change at ffffffc0801531e4
 #4 [ffffffc083c0bce0] psi_task_switch at ffffffc0801536ac
 #5 [ffffffc083c0bd00] __switch_to at ffffffc08112897c
 #6 [ffffffc083c0bd80] __schedule at ffffffc0811295ac
 #7 [ffffffc083c0bde0] schedule at ffffffc081129b34
 #8 [ffffffc083c0be10] rescuer_thread at ffffffc0800fd118
 #9 [ffffffc083c0be70] kthread at ffffffc080102e20
```

unwind irq stack(only support ARM64).
```
crash> dbi -C 0
CPU[0] irq stack:0xffffffc080000000~0xffffffc080004000
[0]Potential backtrace -> FP:0xffffffc080003ec0, LR:0xffffffc080003ec8
PID: 0        TASK: ffffffc0822dccc0  CPU: 0    COMMAND: "swapper/0"
 #0 [ffffffc080003ef0] sched_clock at ffffffc0801dc4dc
 #1 [ffffffc080003f10] sched_clock_cpu at ffffffc080148fec
 #2 [ffffffc080003f20] irqtime_account_irq at ffffffc0801318b8
 #3 [ffffffc080003f80] handle_softirqs at ffffffc0800d7624
 #4 [ffffffc080003fe0] __do_softirq at ffffffc080010200
 #5 [ffffffc080003ff0] ____do_softirq at ffffffc08001f230
--- <IRQ stack> ---
 #6 [ffffffc0822c3b80] call_on_irq_stack at ffffffc08001f1bc
 #7 [ffffffc0822c3bf0] init_thread_union at ffffffc0822c3bec
 #8 [ffffffc0822f9e20] __kvm_nvhe___kcfi_typeid_hyp_unpin_shared_mem at ffffff887ab592fc
```

## ipc
This command dumps the ipc log.

### ipc -a
Display all ipc module info.
```
crash> ipc -a
ipc_log_context  Magic      Version first_page       last_page        write_page       read_page        Name
ffffff80039a3b00 25874452   3       ffffff8007b9c000 ffffff8007b9d000 ffffff8007b9c000 ffffff8007b9c000 glink_probe
ffffff8008ee5700 25874452   3       ffffff8008904000 ffffff8008900000 ffffff8008904000 ffffff8008904000 bcl_0x4700_0
ffffff80088a1800 25874452   3       ffffff8007bb7000 ffffff8007bb4000 ffffff8007bb4000 ffffff8007bb7000 smp2p
ffffff8012f27500 25874452   3       ffffff8008905000 ffffff8012fb7000 ffffff800a038000 ffffff800a038000 rpm-glink
ffffff8012f9ec00 25874452   3       ffffff8012fc6000 ffffff8012fcb000 ffffff8012fc3000 ffffff8012fc3000 qrtr_ns
ffffff8012e2a100 25874452   3       ffffff8003121000 ffffff8003126000 ffffff8003121000 ffffff8003121000 glink_ssr
ffffff80041c9700 25874452   3       ffffff8007bb1000 ffffff800216e000 ffffff8007bb1000 ffffff8007bb1000 mmc0
ffffff8018af1600 25874452   3       ffffff8018e8c000 ffffff8018e8c000 ffffff8018e8c000 ffffff8018e8c000 dma_bam_log
```

### ipc -l 'ipc module name'
Display ipc log.
```
crash> ipc -l bcl_0x4700_0
[ 1.748384640 0x722c8ab9b01]   [kworker/u8:1]: bcl_read_ibat: ibat:0 mA ADC:0x00
[ 1.748404692 0x722c8ab9c80]   [kworker/u8:1]: bcl_read_vbat_tz: vbat:4185 mv ADC:0x54
[ 1.748409536 0x722c8ab9cdd]   [kworker/u8:1]: bcl_read_lbat: LVLbat:5 val:0
[ 1.748486775 0x722c8aba2a8]   [kworker/u8:1]: bcl_read_ibat: ibat:0 mA ADC:0x00
[ 1.748504744 0x722c8aba401]   [kworker/u8:1]: bcl_read_vbat_tz: vbat:4185 mv ADC:0x54
[ 1.748508494 0x722c8aba449]   [kworker/u8:1]: bcl_read_lbat: LVLbat:6 val:0
[ 9.688728102 0x722d1c1e0c3]   [kworker/2:0H]: bcl_read_ibat: ibat:0 mA ADC:0x00
[ 9.688746748 0x722d1c1e227]   [kworker/2:0H]: bcl_read_vbat_tz: vbat:4185 mv ADC:0x54
[ 9.688751227 0x722d1c1e27d]   [kworker/2:0H]: bcl_read_lbat: LVLbat:5 val:0
```

## reg
This command dumps the regulator info.

### reg -a
Display all regulator and consumer info.
```
crash> reg -a
regulator_dev:ffffff8006994800 regulator-dummy open_count:4 use_count:3 bypass_count:0 min_uV:0 max_uV:0 input_uV:0
   regulator:ffffff801e51c000 enable:0 load:0uA 5e94000,mdss_dsi0_ctrl-refgen
   regulator:ffffff801e51c0c0 enable:0 load:0uA 5e94400,mdss_dsi_phy0-gdsc
   regulator:ffffff801ad6cc00 enable:1 load:0uA soc:usb_nop_phy-vcc
   regulator:ffffff800a036780 enable:1 load:0uA regulator.21-SUPPLY
```
### reg -r
Display all regulator info.
```
crash> reg -r
regulator_dev    open use bypass regulator_desc   constraints      min_uV   max_uV   input_uV Name
ffffff8006994800 4    3   0      ffffffeee20a0020 ffffff80067f8d00 0        0        0        regulator-dummy
ffffff8007811800 17   0   0      ffffff8003999048 ffffff80033ebb00 0        0        0        gcc_camss_top_gdsc
ffffff8007813000 1    1   0      ffffff8003999448 ffffff80033eb700 0        0        0        gcc_usb20_prim_gdsc
ffffff8007812000 1    0   0      ffffff8003999c48 ffffff80033eb000 0        0        0        gcc_vcodec0_gdsc
ffffff8007810800 1    0   0      ffffff800a39a048 ffffff8007a39000 0        0        0        gcc_venus_gdsc
```
### reg -c 'name'
Display all consumer info of regulator.
```
crash> reg -c pm5100_l12
Consumers:
   regulator        load       enable Name
   ffffff802a899a80 0uA        0      5c54000,csiphy1-mipi-csi-vdd1
   ffffff802a883780 0uA        0      5c52000,csiphy0-mipi-csi-vdd1
   ffffff801e51ca80 0uA        0      5e94400,mdss_dsi_phy0-vdda-0p9 voltage:[904000uV~904000uV,]
   ffffff801ad6ce40 30000uA    1      1613000.hsphy-vdd voltage:[904000uV~904000uV,]
   ffffff8002204f00 0uA        1      regulator.59-SUPPLY
```

## icc
This command dumps the icc info.

### icc -a
Display all icc provider/node/request info.
```
crash> icc -a
icc_provider:ffffff880264a280 soc:interconnect@0
    icc_node:ffffff8808e67380 avg_bw:0 peak_bw:0 [qup0_core_master]
    icc_node:ffffff8808e67480 avg_bw:1 peak_bw:1 [qup1_core_master]
       icc_req:ffffff885db4b290 avg_bw:1 peak_bw:1 [a94000.i2c]
       icc_req:ffffff8862678710 avg_bw:1 peak_bw:1 [a8c000.i2c]
```
### icc -p
Display all icc provider.
```
crash> icc -p
icc_provider     users Name
ffffff880264a280 18    soc:interconnect@0
ffffff8807352a80 32    1600000.interconnect
ffffff880879ba80 34    1500000.interconnect
ffffff8808798c80 36    1680000.interconnect
ffffff8808799480 6     16c0000.interconnect
```
### icc -n 'provider'
Display all icc node of specified provider by provider name.
```
crash> icc -n 1600000.interconnect
icc_node         id    avg_bw     peak_bw    qcom_icc_node    Name
ffffff8808703980 39    115        14000      ffffffecd52b0c08 qsm_cfg
ffffff882e640500 513   0          0          ffffffecd52b0dc8 qhs_ahb2phy0
ffffff882e640880 514   0          0          ffffffecd52b0f88 qhs_ahb2phy1
ffffff882e640d00 516   0          0          ffffffecd52b1148 qhs_camera_cfg
ffffff8807b34100 517   0          0          ffffffecd52b1308 qhs_clk_ctl
```
### icc -r 'node'
Display all icc request of specified node by node name.
```
crash> icc -r qsm_cfg
icc_req          enabled tag  avg_bw     peak_bw    Name
ffffff8865f38cd0 true    0    0          0          a600000.ssusb
ffffff8857aaa4d0 false   0    1          1          1a88000.i2c
ffffff8857ad0cd0 false   0    1          1          884000.i2c
ffffff882abecad0 false   0    1          1          a94000.i2c
ffffff8857c782d0 false   0    1          1          880000.i3c-master
```

## ccf
This command dumps the clock info.

### ccf -c
Display all clock provider info.
```
crash> ccf -c
clk_provider: clock-controller
   clk_core               rate   req_rate   new_rate rpm   boot  en    prep  clk_hw           Name
   ffffff8017a8d600  1010.0MHZ   310.0MHZ  1010.0MHZ 0     1     1     1     ffffffd3034531a8 gpu_cc_pll0
   ffffff8017a8dc00     0.0MHZ     0.0MHZ     0.0MHZ 0     0     0     0     ffffffd3034533f0 gpu_cc_crc_ahb_clk
   ffffff8017a8dd00     0.0MHZ     0.0MHZ     0.0MHZ 0     0     0     0     ffffffd303453488 gpu_cc_cx_apb_clk
   ffffff8017a8d900  1010.0MHZ    19.2MHZ  1010.0MHZ 0     0     0     0     ffffffd303453520 gpu_cc_cx_gfx3d_clk
```
### ccf -t
Display all clock provider and clock consumers by tree.
```
crash> ccf -t
clk_provider:clock-controller
   clk_core:ffffff8017a8d600  gpu_cc_pll0                                   1010MHZ
   clk_core:ffffff8017a8d900  gpu_cc_cx_gfx3d_clk                           1010MHZ
   clk_core:ffffff8017a8d500  gpu_cc_cx_gfx3d_slv_clk                       1010MHZ
   clk_core:ffffff8017a8df00  gpu_cc_cx_gmu_clk                             19.2MHZ
           clk:ffffff801625a000  --> device:5900000.qcom,kgsl-3d0
```
### ccf -e
Display all enable clock info.
```
crash> ccf -e
=============================================
  Enable Clocks from of_clk_providers list
=============================================
clk_core         Name                                          Rate
ffffff801804ab00 dsi0_phy_pll_out_byteclk                      24.6847MHZ
ffffff801804aa00 dsi0_phy_pll_out_dsiclk                       8.22824MHZ
ffffff8017a8d600 gpu_cc_pll0                                   1010MHZ
```
### ccf -d
Display all disable clock info.
```
crash> ccf -d
=============================================
  Disabled Clocks from of_clk_providers list
=============================================
clk_core         Name                                          Rate
ffffff8017a8d500 gpu_cc_cx_gfx3d_slv_clk                       1010MHZ
ffffff800a68ed00 gpll4                                         806.4MHZ
ffffff800a68ef00 gpll7                                         808MHZ
```
### ccf -p
Display all prepare clock info.
```
crash> ccf -p
=============================================
  Prepare Clocks from of_clk_providers list
=============================================
clk_core         Name                                          Rate
ffffff801804ab00 dsi0_phy_pll_out_byteclk                      24.6847MHZ
ffffff801804aa00 dsi0_phy_pll_out_dsiclk                       8.22824MHZ
ffffff8017a8d600 gpu_cc_pll0                                   1010MHZ
```
## pstore
This command dumps the pstore log info.

### pstore -p
Display pmsg log.
```
crash> pstore -p
25-04-20 19:03:41.000758 1719  2299  1000   I SDM ClstcAlgorithmAdapter::QueryLibraryRequest():711 Get library config 0, rc 0
25-04-20 19:03:41.000766 1719  2299  1000   I SDM ClstcAlgorithmAdapter::QueryLibraryRequest():711 Get library config 0, rc 0
25-04-20 19:03:41.000775 1719  2299  1000   I SDM ClstcAlgorithmAdapter::QueryLibraryRequest():711 Get library config 0, rc 0
25-04-20 19:03:41.000775 7290  7911  1000   I lcomm.qti.axiom Waiting for a blocking GC Alloc
25-04-20 19:03:41.000782 1719  2299  1000   I SDM ClstcAlgorithmAdapter::QueryLibraryRequest():711 Get library config 0, rc 0
25-04-20 19:03:41.000791 1719  2299  1000   I SDM ClstcAlgorithmAdapter::QueryLibraryRequest():711 Get library config 0, rc 0
```