#pragma once
#include <stdint.h>

class FPGA;
uint64_t loadElf(FPGA *fpga, const char *elf_filename, size_t max_mem_size, bool set_htif);
