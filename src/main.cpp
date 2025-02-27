
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <vector>

#include "fpga.h"
#include "loadelf.h"
#include "util.h"

#define DEFAULT_DMA_ENABLED 0
#ifdef SIMULATION
#define DEFAULT_XDMA_ENABLED 0
#else
#define DEFAULT_XDMA_ENABLED 0 // XXX make DMA work.
#endif

#define DEBUG_LOOP 0

// we should read this from the dtb
#define BOOTROM_BASE  (0x70000000)
#define BOOTROM_LIMIT (0x70010000)
#define DEVICETREE_OFFSET (0x20)

const struct option long_options[] = {
    { "block", required_argument, 0, 'B' },
    { "dma",     optional_argument, 0, 'D' },
    { "dtb",     optional_argument, 0, 'd' },
    { "elf",     optional_argument, 0, 'e' },
    { "help",    no_argument, 0, 'h' },
    { "htif-console",  optional_argument, 0, 'H' },
    { "tun",      required_argument,       0, 't' },
    { "uart",          optional_argument, 0, 'U' },
    { "uart-console",  optional_argument, 0, 'U' },
    { "usemem",  no_argument,       0, 'M' },
    { "virtio-console", optional_argument, 0, 'C' },
    { "xdma",     optional_argument, 0, 'X' },
    { "debug-log", no_argument,     0, 'L' },
    { "no-iocap", no_argument, 0, 'I' },
    { 0,         0,                 0, 0 }
};

void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [options] [elf ...]\r\n", name);
    for (const struct option *option = long_options; option->name != 0; option++) {
	if (option->has_arg == required_argument) {
	    fprintf(stderr, "        --%s arg\r\n", option->name);
	} else if (option->has_arg == optional_argument) {
	    fprintf(stderr, "        --%s [arg]\r\n", option->name);
	} else {
	    fprintf(stderr, "        --%s\r\n", option->name);
	}
    }
}

int main(int argc, char * const *argv)
{
    const char *bootrom_filename = 0;
    const char *dtb_filename = 0;
    std::vector<std::string> elf_files;
    int cpuverbosity = 0;
    uint32_t entry = 0;
#if DEBUG_LOOP
    int sleep_seconds = 1;
#endif
    int usemem = 0;
    const char *tun_iface = 0;
    int tv = 0;
    int enable_virtio_console = 0;
    uint64_t htif_enabled = 0;
    uint64_t uart_enabled = 0;
    int dma_enabled = DEFAULT_DMA_ENABLED;
    int xdma_enabled = DEFAULT_XDMA_ENABLED;
    std::vector<std::string> block_files;
    int debug_log = 0;
    bool virtio_iocap = true;

    while (1) {
        int option_index = optind ? optind : 1;
        int c = getopt_long(argc, argv, "B:C:d:D:e:hH:LMp:U:X:I:",
                             long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'B':
            block_files.push_back(std::string(optarg));
            break;
        case 'C':
            if (optarg) {
                enable_virtio_console = strtoul(optarg, 0, 0);
            } else {
                enable_virtio_console = 1;
            }
            break;
        case 'D':
            if (optarg) {
                dma_enabled = strtoul(optarg, 0, 0);
            } else {
                dma_enabled = 1;
            }
	    //fprintf(stderr, "DMA %d\r\n", dma_enabled);
            break;
        case 'e':
            elf_files.push_back(std::string(optarg));
            break;
        case 'E':
            entry = strtoul(optarg, 0, 0);
            break;
        case 'h':
            usage(argv[0]);
            return 2;
        case 'M':
            usemem = 1;
            break;
#if DEBUG_LOOP
        case 's':
            sleep_seconds = strtoul(optarg, 0, 0);
            break;
#endif
        case 't':
            tun_iface = optarg;
            break;
        case 'v':
            cpuverbosity = strtoul(optarg, 0, 0);
            break;
        case 'U':
            if (optarg) {
                uart_enabled = strtoul(optarg, 0, 0);
            } else {
                uart_enabled = 1;
            }
	    //fprintf(stderr, "UART %d\r\n", uart_enabled);
            break;
        case 'X':
            if (optarg) {
                xdma_enabled = strtoul(optarg, 0, 0);
            } else {
                xdma_enabled = 1;
            }
	    //fprintf(stderr, "XDMA %d\r\n", xdma_enabled);
            break;
        case 'L':
            debug_log = 1;
            break;
        case 'I':
            virtio_iocap = false;
            break;
        }
    }

    // Enable a UART by default if no other terminal I/O requested
    if (enable_virtio_console == 0 && htif_enabled == 0 && uart_enabled == 0) {
        uart_enabled = 1;
    }

    setEnableDebugLog(debug_log);

    while (optind < argc) {
        elf_files.push_back(argv[optind++]);
    }
    // A vestige from a previous time: bootrom_filename and elf_files are not used for the rest of this program.
    // if (!bootrom_filename && !elf_files.size()) {
    //     usage(argv[0]);
    //     return -1;
    // }

    // allocate a memory object for Rom
    // Samuel note: This is also unused/uninitialized.
    // Rom is mapped into some of the MMIO memory space (see FPGA::emulated_mmio_respond)
    // and effectively leaks uninitialized memory to the consumer MMIO.
    size_t rom_alloc_sz = 1024*1024;
    uint8_t *romBuffer = (uint8_t *)malloc(rom_alloc_sz);
    debugLog("romBuffer=%lx\r\n", (long)romBuffer);

    Rom rom = { BOOTROM_BASE, BOOTROM_LIMIT, (uint64_t *)romBuffer };

    // Initialize the FPGA singleton before we use it
    fpga_singleton_init(1, rom, tun_iface, virtio_iocap); // What is/was IfcNames_FPGA_ResponseH2S? I put "1" instead; it's an ID of some sort.
    fpga->set_uart_enabled(uart_enabled);

    for (std::string block_file: block_files) {
        fpga->get_virtio_devices().add_virtio_block_device(block_file);
    }

    uint32_t *bootInstrs = (uint32_t *)romBuffer;
    bootInstrs[0] = 0x0000006f; // loop forever
    bootInstrs[1] = 0x0000006f; // loop forever

    if (enable_virtio_console) {
        debugLog("Enabling virtio console\r\n");
        fpga->get_virtio_devices().add_virtio_console_device();
    }

    if (dtb_filename) {
        copyFile((char *)romBuffer + DEVICETREE_OFFSET, dtb_filename, rom_alloc_sz - 0x10);
    }

    // Start up vitio device emulation
    fpga->start_io();

    while (1) {
        if (fpga->emulated_mmio_has_request())
            fpga->emulated_mmio_respond();
        else usleep(10000); // Wait in hope of a new request.
    }
    
    int exit_code = fpga->join_io();
    if (exit_code == EXIT_CODE_RESET) {
        fpga->get_virtio_devices().reset();
    }
    
    return exit_code;
}
