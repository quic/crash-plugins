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

#include "t32.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(T32)
#endif

class TCR_EL1 : public ParserPlugin {
public:
    uint64_t value;
    TCR_EL1(bool is_cortexa) {
        if (!is_cortexa) {
            value = 0x00000032B5193519;
            std::unordered_map<uint64_t, uint8_t> tg1_granule_size = {
                {4096,  0b10},
                {16384, 0b01},
                {65536, 0b11}
            };
            std::unordered_map<uint64_t, uint8_t> tg0_granule_size = {
                {4096,  0b00},
                {16384, 0b10},
                {65536, 0b01}
            };
            set_field(31, 30, tg1_granule_size.count(page_size) ? tg1_granule_size[page_size] : 0b10); // TG1
            set_field(15, 14, tg0_granule_size.count(page_size) ? tg0_granule_size[page_size] : 0b00); // TG0
            uint8_t t_sz = 64 - std::stoi(get_config_val("CONFIG_ARM64_VA_BITS"));
            set_field(21, 16, t_sz); // T1SZ
            set_field(5, 0, t_sz);   // T0SZ
        } else {
            value = 0x00000012B5193519;
            // RES0 and RES1 are reserved and not modified
        }
    }
    void cmd_main(void) override {}
    void init_offset(void) override {}
    void init_command(void) override {}

private:
    void set_field(uint8_t msb, uint8_t lsb, uint64_t field_value) {
        uint64_t mask = ((1ULL << (msb - lsb + 1)) - 1) << lsb;
        value = (value & ~mask) | ((field_value << lsb) & mask);
    }
};

void T32::cmd_main(void) {
    int c;
    std::string win_path;
    std::string cpu_type;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "s:c:")) != EOF) {
        switch(c) {
            case 's':
                win_path.assign(optarg);
                break;
            case 'c':
                cpu_type.assign(optarg);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs){
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }
    if (std::find(cpu_types.begin(), cpu_types.end(), cpu_type) == cpu_types.end()) {
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    parser_t32(win_path, cpu_type);
}

void T32::init_command(void) {
    cmd_name = "t32";
    help_str_list={
        "t32",                            /* command name */
        "generate the launch_t32.bat script",        /* short description */
        "-s \n"
            "  -c\n"
            "  This command generate the launch_t32.bat script. At present, we support CORTEXA53, CORTEXA7, ARMv8.2-A and ARMV9-A.",
        "\n",
        "EXAMPLES",
        "  generate the launch_t32.bat script:",
        "    %s> t32 -s <the dump file path on Windows> -c <cpu_type>",
        "    Saved launch_t32.bat to path/t32/launch_t32.bat",
        "\n",
    };
}

void T32::init_offset(void) {
}

T32::T32(){
    // do_init_offset = false;
}

std::string T32::create_t32_path(const std::string& filename) {
    std::stringstream t32_path = get_curpath();
    t32_path << "/t32/";
    mkdir(t32_path.str().c_str(), 0777);
    t32_path << filename;
    return t32_path.str();
}

void T32::parser_t32(std::string& win_path, std::string& cpu_type){
    windows_path = win_path;
    parser_t32_launch_config();
    parser_t32_launch_cmm(cpu_type);
    parser_t32_launch_bat();
}

void T32::parser_t32_launch_config() {
    std::string path = create_t32_path(t32_launch_config);
    FILE* config_file = fopen(path.c_str(), "wb");
    if (!config_file) {
        fprintf(fp, "Can't open %s\n", path.c_str());
        return;
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(20000, 30000);
    int port = dis(gen);
    std::ostringstream oss;
    oss << "OS=\n"
        << "ID=T32_1000002\n"
        << "TMP=C:\\TEMP\n"
        << "SYS=C:\\T32\n"
        << "HELP=C:\\T32\\pdf\n"
        << "\n"
        << "PBI=SIM\n"
        << "\n"
        << "SCREEN=\n"
        << "FONT=LARGE\n"
        << "HEADER=Trace32-ScorpionSimulator\n"
        << "\n"
        << "PRINTER=WINDOWS\n"
        << "\n"
        << "RCL=NETASSIST\n"
        << "PACKLEN=1024\n"
        << "PORT=" << port << "\n";

    fwrite(oss.str().c_str(), oss.str().size(), 1, config_file);
    fclose(config_file);
    // fprintf(fp, "Saved %s to %s\n", t32_launch_config.c_str(), path.c_str());
}


void T32::parser_t32_launch_cmm(std::string& cpu_type){
    std::string path = create_t32_path(t32_launch_cmm);
    FILE* cmm_file = fopen(path.c_str(), "wb");
    if (!cmm_file) {
        fprintf(fp, "Can't open %s\n", path.c_str());
        return;
    }

    bool is_cortex_a53 = false;
    ulong kaslr_offset = kt->relocate * -1;
    ulong swapper_pg_dir_addr = virt_to_phy(csymbol_value("swapper_pg_dir"));
    ulong ttbr = swapper_pg_dir_addr;

    std::ostringstream oss;
    oss << "title \"" << windows_path << "\"\n";

    if (BITS64() && is_cortex_a53) {
        oss << "sys.cpu " << cpu_type <<"\n";
    } else {
        if (cpu_type == "ARMv8.2-A") {
            oss << "sys.cpu CORTEXA55\n";
        } else {
            oss << "sys.cpu " << cpu_type << "\n";
        }
        oss << "SYStem.Option MMUSPACES ON\n"
            << "SYStem.Option ZONESPACES OFF\n";
    }
    oss << "sys.up\n";

    if(is_cortex_a53 && !BITS64()){
         oss << "r.s m 0x13\n";
    }
    oss << extract_load_binary("dump_info.txt").str();
    if(BITS64()){
        oss << "Data.Set SPR:0x30201 %Quad 0x" << std::hex << swapper_pg_dir_addr << "\n";
        auto trc_el1 = std::make_shared<TCR_EL1>(is_cortex_a53);
        oss << "Data.Set SPR:0x30202 %Quad 0x" << std::setw(16) << std::setfill('0') << std::uppercase << trc_el1->value << "\n";
        if (is_cortex_a53) {
            oss << "Data.Set SPR:0x30A20 %Quad 0x000000FF440C0400\n"
                << "Data.Set SPR:0x30A30 %Quad 0x0000000000000000\n"
                << "Data.Set SPR:0x30100 %Quad 0x0000000034D5D91D\n";
        } else if (cpu_type == "ARMV9-A") {
            oss << "Data.Set SPR:0x30A20 %Quad 0x000000FF440C0400\n"
                << "Data.Set SPR:0x30A30 %Quad 0x0000000000000000\n"
                << "Data.Set SPR:0x30100 %Quad 0x0000000084C5D93D\n";
        } else {
            oss << "Data.Set SPR:0x30A20 %Quad 0x000000FF440C0400\n"
                << "Data.Set SPR:0x30A30 %Quad 0x0000000000000000\n"
                << "Data.Set SPR:0x30100 %Quad 0x0000000004C5D93D\n";
        }
        oss << "Register.Set NS 1\n"
            << "Register.Set CPSR 0x1C5\n";
    } else {
        // oss << "PER.S.F C15:0x102 %L 0x" << std::hex << std::lowercase << (ttbr + 0x4000) << "\n";
        oss << "PER.S.simple C15:0x1 %L 0x1\n"
            << "PER.S.simple C15:0x2 %L 0x" << std::hex << ttbr << "\n"
            << "PER.S.F C15:0x202 %L 0x80030000\n"
            << "mmu.on\n"
            << "mmu.scan\n";
    }
    if(kaslr_offset){
        oss << "data.load.elf " << windows_path << "\\vmlinux 0x" << kaslr_offset << " /nocode\n";
    } else {
        oss << "data.load.elf " << windows_path << "\\vmlinux " << " /nocode\n";
    }
    if (BITS64()) {
        oss << "TRANSlation.COMMON NS:0xF000000000000000--0xffffffffffffffff\n"
            << "trans.tablewalk on\n"
            << "trans.on\n";
        if (cpu_type != "ARMV9-A") {
            oss << "MMU.Delete\n"
                << "MMU.SCAN PT 0xFFFFFF8000000000--0xFFFFFFFFFFFFFFFF\n"
                << "mmu.on\n"
                << "mmu.pt.list 0xffffff8000000000\n";
        }
    }
    if (BITS64()) {
        oss << "IF OS.DIR(\"C:\\T32\\demo\\arm64\")\n"
            << "(\n"
            << "task.config C:\\T32\\demo\\arm64\\kernel\\linux\\awareness\\linux.t32 /ACCESS NS:\n"
            << "menu.reprogram C:\\T32\\demo\\arm64\\kernel\\linux\\awareness\\linux.men\n"
            << ")\n"
            << "ELSE\n"
            << "(\n"
            << "task.config C:\\T32\\demo\\arm\\kernel\\linux\\awareness\\linux.t32 /ACCESS NS:\n"
            << "menu.reprogram C:\\T32\\demo\\arm\\kernel\\linux\\awareness\\linux.men\n"
            << ")\n";
    } else {
        oss << "task.config c:\\t32\\demo\\arm\\kernel\\linux\\linux-3.x\\linux3.t32\n"
            << "menu.reprogram c:\\t32\\demo\\arm\\kernel\\linux\\linux-3.x\\linux.men\n";
    }
    if (THIS_KERNEL_VERSION >= LINUX(5, 10, 0)) {
        oss << "IF OS.DIR(\"C:\\T32\\demo\\arm64\")\n"
            << "(\n"
            << "sYmbol.AUTOLOAD.CHECKCOMMAND  \"do C:\\T32\\demo\\arm64\\kernel\\linux\\awareness\\autoload.cmm\"\n"
            << ")\n"
            << "ELSE\n"
            << "(\n"
            << "sYmbol.AUTOLOAD.CHECKCOMMAND  \"do C:\\T32\\demo\\arm\\kernel\\linux\\etc\\gdb\\gdb_autoload.cmm\"\n"
            << ")\n"
            << "y.spath = " << windows_path << "\\kernel_modules\n"
            << "y.spath += " << windows_path << "\\kernel_modules\n"
            << "TASK.sYmbol.Option AutoLoad Module\n"
            << "TASK.sYmbol.Option AutoLoad noprocess\n"
            << "sYmbol.AutoLOAD.List\n"
            << "sYmbol.AutoLOAD.CHECK\n";
    } else {
        ;
    }
    oss << "task.dtask\n"
        << "v.v  %ASCII %STRING linux_banner\n"
        << ";" << "symbol.sourcepath.setrecursedir <path of source code>\n"
        << ";" << "v.v (<datatype>*) <ADDRS>\n";

    fwrite(oss.str().c_str(), oss.str().size(), 1, cmm_file);
    fclose(cmm_file);
    // fprintf(fp, "Saved %s to %s\n", t32_launch_cmm.c_str(), path.c_str());
}

void T32::parser_t32_launch_bat() {
    std::string path = create_t32_path(t32_launch_bat);
    FILE* bat_file = fopen(path.c_str(), "wb");
    if (!bat_file) {
        fprintf(fp, "Can't open %s\n", path.c_str());
        return;
    }

    std::string t32_binary = BITS64() ? "C:\\T32\\bin\\windows64\\t32MARM64.exe" : "C:\\T32\\bin\\windows64\\t32MARM.exe";
    std::ostringstream oss;
    oss << "start "
        << t32_binary
        << " -c "
        << windows_path << "\\t32/t32_config.t32, "
        << windows_path << "\\t32/t32_startup_script.cmm\n";

    fwrite(oss.str().c_str(), oss.str().size(), 1, bat_file);
    fclose(bat_file);
    fprintf(fp, "Saved %s to %s\n", t32_launch_bat.c_str(), path.c_str());
}


std::ostringstream T32::extract_load_binary(const std::string& file_path) {
    std::ostringstream oss;
    const std::string base_path = get_curpath().str();
    FILE* file = fopen(file_path.c_str(), "r");
    if (!file) {
        fprintf(fp, "Can't open %s\n", file_path.c_str());
        return oss;
    }
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)) {
        std::string line(buffer);
        if (line.find("OCIMEM") != std::string::npos || line.find("PIMEM") != std::string::npos || line.find("DDRCS") != std::string::npos) {
            std::istringstream iss(line);
            std::string token;
            std::vector<std::string> tokens;
            while (iss >> token) {
                tokens.push_back(token);
            }
            if (tokens.size() >= 5) {
                std::string base_address = tokens[1];
                std::string file_name = tokens.back();
                oss << "data.load.binary " << windows_path << "\\" << file_name << " " << base_address << std::endl;
            }
        }
    }
    fclose(file);
    return oss;
}

#pragma GCC diagnostic pop
