```
Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause-Clear
```

# Overall
We have developed the plugins that can gather more information based on crash-utility, including both kernel space and user space. This enhances our debugging efficiency.

# How to start

```
sudo apt-get install cmake  // cmake >= 3.21.1
```
```
$ sudo apt-get install gcc-multilib g++-multilib
```

# How to build

We support both single-module and multi-module compilation, managed through BUILD_TARGET_TOGETHER in build.sh.

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

To load the module's commands to a running crash-8.0.4+ session, enter:

```
crash> extend <path-to>/output/arm64/plugins.so or extend <path-to>/output/arm64/${module}.so
```

Supprot command:
|  command   |    arm64  | arm       |
|  --------  | --------  | --------  |
| cma        | x         | x         |
| buddy      | x         | x         |
| memblock   | x         | x         |
| reserved   | x         | x         |
| vmalloc    | x         | x         |
| binder     | x         | x         |
| dts        | x         | x         |
| procrank   | x         | x         |
| coredump   | x         | x         |
| workqueue  | x         | x         |
| slub       | x         | x         |
| zram       | x         | x         |
| partition  | x         | x         |
| pageowner  | x         | x         |
| meminfo    | x         | x         |


## usage
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
1. Add the header file: demo.h
```
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef DEMO_DEFS_H_
#define DEMO_DEFS_H_

#include "plugin.h"

class Demo: public PaserPlugin {
public:
    Demo();

    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(Demo)
};

#endif // DEMO_DEFS_H_
```
2. Add the Demo.cpp file
```
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "demo.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Demo)
#endif

void Demo::cmd_main(void) {
    int c;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "a")) != EOF) {
		switch(c) {
            case 'a':
                do_somethins();
                break;
            default:
                argerrs++;
                break;
		}
	}
    if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);
}

Demo::Demo():PaserPlugin(){
    cmd_name = "demo";
    help_str_list={
	"demo",					/* command name */
	"your description",		/* short description */
    };
    initialize();
}

#pragma GCC diagnostic pop
```
3. Add the build rule in CMakeLists.txt, it will output the demo.so, now you can use it.
```
add_library(demo SHARED
            ${PLUGIN_SOURCES}
            demo.cpp)
set_target_properties(demo PROPERTIES PREFIX "")
```
4. if you want to add the module to single-module. please follow the steps in plugins.cpp
  - include your header file
    ```
    #include "demo.h"
    ```
  - Add the global unique_ptr
    ```
    std::unique_ptr<Demo>   Demo::instance = nullptr;
    ```
  - register your module in function plugin_init
    ```
    { &Demo::instance->cmd_name[0], &Demo::wrapper_func, Demo::instance->cmd_help, 0 },
    ```
  - Destory your module in function plugin_fini
    ```
    Demo::instance.reset();
    ```
  - Add the build rule in CMakeLists.txt
    ```
    list(APPEND PLUGIN_SOURCES
            ...
            demo.cpp)
    ```

# Tested Kernels
- 5.4 to 6.6

# Related Links
- https://github.com/quic/crash-plugins.git

# Author
 - quic_wya@quicinc.com