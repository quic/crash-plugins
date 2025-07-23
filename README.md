# Overall
We've developed plugins based on crash-utility that can collect more information, covering both kernel space and user space. This improves our debugging efficiency.

![alt text](doc/image.png)

# How to start

```
sudo apt-get install cmake  // cmake >= 3.21.1
```
```
sudo dpkg --add-architecture i386
```
```
sudo apt-get update
```
```
sudo apt install gcc-multilib g++-multilib libzstd-dev libzstd-dev:i386 libelf-dev libelf-dev:i386 libsystemd-dev libsystemd-dev:i386 pkg-config
```

# How to build

We can compile each plugin as a separate library or compile all plugins together. Use the BUILD_TARGET_TOGETHER macro in build.sh to configure it.

## single-module (by defalut)
```
cmake -DCMAKE_C_COMPILER="/usr/bin/gcc"   \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE="Debug"          \
      -DCMAKE_BUILD_TARGET_ARCH="arm64"   \
      -DBUILD_TARGET_TOGETHER="1"         \
      CMakeLists.txt                      \
      -B output/arm64
```

## multi-module
```
cmake -DCMAKE_C_COMPILER="/usr/bin/gcc"   \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE="Debug"          \
      -DCMAKE_BUILD_TARGET_ARCH="arm64"   \
      CMakeLists.txt                      \
      -B output/arm64
```

## Build
```
$ ./build.sh
```

# How to use

To load the module's commands to a running crash-8.0.6+ session, enter:

```
crash> extend <path-to>/output/arm64/plugins.so or extend <path-to>/output/arm64/${module}.so
```

Support module:

|  module       |    arm64  |    arm    |    comment                                           |
|  --------     | --------  | --------  |    --------                                          |
| binder        | √         | √         | parser binder log/node/ref/thread/proc/buffer info   |
| slub info     | √         | √         | parser slub detail memory info                       |
| slub poison   | √         | √         | check slub object memory poison                      |
| slub trace    | √         | √         | parser slub object trace                             |
| procrank      | √         | √         | parser vss/rss/pss/uss of process                    |
| cma           | √         | √         | parser cma info                                      |
| device tree   | √         | √         | parser device tree                                   |
| memblock      | √         | √         | parser memblock info                                 |
| device driver | √         | √         | parser device driver/char/block device               |
| dmabuf        | √         | √         | parser dma-buf info                                  |
| workqueue     | √         | √         | parser workqueue info                                |
| reserved mem  | √         | √         | parser reserved memory info                          |
| iomem         | √         | √         | parser memory layout info                            |
| vmalloc       | √         | √         | parser vmalloc info                                  |
| partition     | √         | √         | parser partition info                                |
| pageowner     | √         | √         | parser pageowner info                                |
| buddy         | √         | √         | parser memory node/zone/buddy info                   |
| zram          | √         | √         | parser zram detail info                              |
| swap          | √         | √         | parser swap info and provider API to userspace parser|
| rtb           | √         | √         | parser rtb log                                       |
| cpu           | √         | √         | parser cpu freq and policy info                      |
| coredump      | √         | √         | dump the coredump info                               |
| thermal       | √         | √         | parser all thermal zone temperature info             |
| meminfo       | √         | √         | parser meminfo                                       |
| watchdog      | √         | √         | parser watchdog info                                 |
| pagecache     | √         | √         | parser pagecache for every file                      |
| debugimage    | √         | √         | parser debug image info                              |
| ipc log       | √         | √         | parser ipc log                                       |
| regulator     | √         | √         | parser regulator info                                |
| icc           | √         | √         | parser icc info                                      |
| clock         | √         | √         | parser clock info                                    |
| pstore        | √         | √         | parser pstore log                                    |
| boot          | √         | √         | parser pmic and boot log                             |
| socinfo       | √         | √         | parser socinfo and commandline                       |
| sched         | √         | √         | parser task sched info                               |
| systemd       | √         | √         | parser journal log                                   |
| t32           | √         | √         | generate the launch_t32.bat script                   |


|  module       |   Android-11.0(30)  |  >Android-12.0(31)  |      comment               |
|  --------     | ------------------- | ------------------- | -------------------        |
| property      | √                   | √                   |   parser property info     |
| logcat        | √                   | √                   |   parser logcat log        |
| surfaceflinger| √                   | √                   |   parser the layer info    |

## usage
See [USAGE.md](USAGE.md)
```
crash> help binder

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


DESCRIPTION
  This command dumps the binder log information of a specified process.
       -p  pid argument.


EXAMPLES
  Display all binder proc states:
    crash> binder -a
       proc 7312
       context hwbinder
           thread 7335: l 00 need_return 0 tr 0


  Display specific process binder states:
    crash> binder -p 7312
       proc 7312
       context hwbinder
           thread 7335: l 00 need_return 0 tr 0
```
```
crash> binder -r
binder_proc:0xffffff801a432c00 ndroid.contacts [4346] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:6 requested:0 started:2 ready:3
  binder_ref:0xffffff806c9b0c00 id:117829 desc:7 s:1 w:1 death:0x0 -> node_id:6183 binder_proc:0xffffff80195ed000 system_server[1047]
  binder_ref:0xffffff806883a180 id:117825 desc:3 s:1 w:1 death:0x0 -> node_id:4022 binder_proc:0xffffff80195ed000 system_server[1047]
  binder_ref:0xffffff8067788000 id:117799 desc:1 s:1 w:1 death:0x0 -> node_id:5525 binder_proc:0xffffff80195ed000 system_server[1047]
  binder_ref:0xffffff805a317000 id:117762 desc:0 s:1 w:1 death:0x0 -> node_id:1 binder_proc:0xffffff801de62800 servicemanager[446]
  binder_ref:0xffffff806883ad00 id:117824 desc:2 s:1 w:1 death:0x0 -> node_id:4413 binder_proc:0xffffff80195ed000 system_server[1047]
  binder_ref:0xffffff8046048400 id:117827 desc:5 s:1 w:1 death:0x0 -> node_id:8305 binder_proc:0xffffff80195ed000 system_server[1047]
  binder_ref:0xffffff8066a2b700 id:117826 desc:4 s:1 w:1 death:0x0 -> node_id:5906 binder_proc:0xffffff80195ed000 system_server[1047]
```

# How to develop
1. If you want to build it into plugins.so, please follow the steps.
     - Add your header file.
       ```
       /**
       * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

       #ifndef DEMO_DEFS_H_
       #define DEMO_DEFS_H_

       #include "plugin.h"

       class Demo: public ParserPlugin {
       public:
           Demo();

           void cmd_main(void) override;
           void init_offset(void) override;
           void init_command(void) override;
           DEFINE_PLUGIN_INSTANCE(Demo)
       };

       #endif // DEMO_DEFS_H_
       ```
     - Implement your parser in cpp file.
       ```
       /**
       * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

       #include "demo.h"

       #pragma GCC diagnostic push
       #pragma GCC diagnostic ignored "-Wpointer-arith"

       void Demo::cmd_main(void) {
           int c;
           if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
           while ((c = getopt(argcnt, args, "a")) != EOF) {
               switch(c) {
                   case 'a':
                       do_somethings();
                       break;
                   default:
                       argerrs++;
                       break;
           }
         }
           if (argerrs)
           cmd_usage(pc->curcmd, SYNOPSIS);
       }

       /* It will be called automatically. */
       void Demo::init_command(void) {
           cmd_name = "demo";
           help_str_list={
           "demo",                    /* command name */
           "your description",        /* short description */
           };
       }

       void Demo::init_offset(void) {
         /* If your parser needs to initialize offsets, please do so here. */
         /* If the offset belongs to a driver module, set do_init_offset = false in the constructor. Then, initialize the offset in here and call it from cmd_main(). */
       }
       ```
     - Include your header file to plugins.cpp
       ```
       #include "demo.h"
       ```
     - Add the shared_ptr to plugins.cpp
       ```
       std::shared_ptr<Demo>   Demo::instance = nullptr;
       ```
     - Register your module to plugins.cpp in function plugin_init
       ```
       plugins.push_back(make_and_init<Demo>());
       ```
     - Add the build rule in CMakeLists.txt
       ```
       list(APPEND PLUGIN_SOURCES
           ...
           demo.cpp)
       ```
2. If you want to add the module to the single-module. please follow the steps in plugins.cpp
   - Add your header file.
       ```
       /**
       * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

       #ifndef DEMO_DEFS_H_
       #define DEMO_DEFS_H_

       #include "plugin.h"

       class Demo: public ParserPlugin {
       public:
           Demo();

           void cmd_main(void) override;
           void init_offset(void) override;
           void init_command(void) override;
           DEFINE_PLUGIN_INSTANCE(Demo)
       };

       #endif // DEMO_DEFS_H_
       ```
    - Register your parser using DEFINE_PLUGIN_COMMAND(Demo) in your cpp file.
       ```
       /**
       * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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
       #include "demo.h"
       #pragma GCC diagnostic push
       #pragma GCC diagnostic ignored "-Wpointer-arith"

       DEFINE_PLUGIN_COMMAND(Demo)

       void Demo::cmd_main(void) {
           int c;
           if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
           while ((c = getopt(argcnt, args, "a")) != EOF) {
               switch(c) {
                   case 'a':
                       do_somethings();
                       break;
                   default:
                       argerrs++;
                       break;
           }
         }
           if (argerrs)
           cmd_usage(pc->curcmd, SYNOPSIS);
       }
       /* It will be called automatically. */
       void Demo::init_command(void) {
           cmd_name = "demo";
           help_str_list={
           "demo",                    /* command name */
           "your description",        /* short description */
           };
       }
       void Demo::init_offset(void) {
         /* If your parser needs to initialize offsets, please do so here. */
         /* If the offset belongs to a driver module, set do_init_offset = false in the constructor. Then, initialize the offset in here and call it from cmd_main(). */
       }
       ```
   - Add the build rule in CMakeLists.txt
       ```
       add_library(demo SHARED
               ${PLUGIN_SOURCES}
               demo.cpp)
       set_target_properties(demo PROPERTIES PREFIX "")
       target_link_libraries(demo)
       ```

# Tested Kernels
- 5.4 to 6.6

# Related Links
- https://github.com/quic/crash-plugins.git
- https://crash-utility.github.io/

# Author
 - quic_wya@quicinc.com

# License
 - This project is licensed under the [GPL v2 License](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html). See [LICENSE.txt](LICENSE.txt) for the full license text.
