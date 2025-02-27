
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

extern "C" {
#include "virtio.h"
#include "iomem.h"
}

#include "fpga.h"
#include "virtiodevices.h"
#include "util.h"
#include <cassert>

static int debug = 0;


void fpga_set_irq(void *opaque, int irq_num, int level)
{
    if (debug) fprintf(stderr, "%s: irq_num=%d level=%d\r\n", __FUNCTION__, irq_num, level);
    if (level)
      fpga->irq_set_levels(1 << (irq_num+2));
    else
      fpga->irq_clear_levels(1 << (irq_num+2));
}

static void console_write_data(void *opaque, const uint8_t *buf, int buf_len)
{
    fwrite(buf, 1, buf_len, stdout);
    fflush(stdout);
}

static int console_read_data(void *opaque, uint8_t *buf, int len)
{
    int ret = read((int)(intptr_t)opaque, buf, len);
    if (ret < 0)
        return 0;

    return ret;
}

VirtioDevices::VirtioDevices(int first_irq_num, const char *tun_ifname, bool virtio_iocap)
  : virtio_iocap(virtio_iocap), tun_ifname(tun_ifname) {
    mem_map = phys_mem_map_init();
    irq = (IRQSignal *)mallocz(32 * sizeof(IRQSignal));
    irq_num = first_irq_num;
    virtio_bus = (VIRTIOBusDef *)mallocz(sizeof(*virtio_bus));
    virtio_bus->mem_map = mem_map;
    virtio_bus->addr = 0x40000000;

    for (int i = 0; i < 32; i++)
        irq_init(&irq[i], fpga_set_irq, (void *)22, i);

    // set up a network device
    virtio_bus->irq = &irq[irq_num++];

    #if !defined(CONFIG_TUN) && !defined(CONFIG_SLIRP)
    #error "Neither TUN networking or SLIRP networking are available!"
    #endif
    if (tun_ifname) {
        #ifdef CONFIG_TUN
        ethernet_device = tun_open(tun_ifname);
        #else
        fprintf(stderr, "tinyemu was not compiled with TUN network support, so can't open the tunnel '%s'.\n", tun_ifname);
        abort();
        #endif
    } else {
        #ifdef CONFIG_SLIRP
        ethernet_device = slirp_open();
        #else
        fprintf(stderr, "tinyemu was not compiled with SLIRP network support, and a TUN tunnel wasn't selected, so can't initialize the network.\n");
        abort();
        #endif
    }

    virtio_net = virtio_net_init(virtio_bus, ethernet_device, virtio_iocap);
    debugLog("ethernet device %p virtio net device %p at addr %08lx\r\r\n", ethernet_device, virtio_net, virtio_bus->addr);

    // set up an entropy device
    virtio_bus->addr += 0x1000;
    virtio_bus->irq = &irq[irq_num++];
    virtio_entropy = virtio_entropy_init(virtio_bus);
    debugLog("virtio entropy device %p at addr %08lx\r\r\n", virtio_entropy, virtio_bus->addr);
}

VirtioDevices::~VirtioDevices() {
    if (console) {
        close((int)(intptr_t)console->opaque);
    }
}

void VirtioDevices::add_virtio_block_device(std::string filename)
{
    // See VirtioDevices::start() for why this doesn't work. TODO - FIX
    assert(virtio_block == NULL && "Can't create multiple virtio_block devices");
    // set up a block device
    virtio_bus->addr += 0x1000;
    virtio_bus->irq = &irq[irq_num++];
    block_device = block_device_init(filename.c_str(), BF_MODE_RW);
    debugLog("block device %s (%p)\r\r\n", filename.c_str(), block_device);
    virtio_block = virtio_block_init(virtio_bus, block_device, virtio_iocap);
    debugLog("virtio block device %p at addr %08lx\r\r\n", virtio_block, virtio_bus->addr);

}

void VirtioDevices::add_virtio_console_device()
{
    console = (CharacterDevice *)malloc(sizeof(*console));
    console->opaque = (void *)(intptr_t)-1;
    console->read_data = console_read_data;
    console->write_data = console_write_data;
    virtio_bus->addr += 0x1000;
    virtio_bus->irq = &irq[irq_num++];
    virtio_console = virtio_console_init(virtio_bus, console);
}

void VirtioDevices::set_virtio_stdin_fd(int fd)
{
    console->opaque = (void *)(intptr_t)fd;
}

void VirtioDevices::set_virtio_dma_funcs()
{
    virtio_dma_init(fpga_singleton_dma_read, fpga_singleton_dma_write);
}

bool VirtioDevices::has_virtio_console_device()
{
    return virtio_console != nullptr;
}

PhysMemoryRange *VirtioDevices::get_phys_mem_range(uint64_t paddr)
{
    return ::get_phys_mem_range(mem_map, paddr);
}

uint8_t *VirtioDevices::phys_mem_get_ram_ptr(uint64_t paddr, BOOL is_rw)
{
    return ::phys_mem_get_ram_ptr(mem_map, paddr, is_rw);
}

void VirtioDevices::process_io()
{
    int stdin_fd;
    int fd_max = -1;
    fd_set rfds, wfds, efds;
    int delay = 10; // ms
    struct timeval tv;
    int stop_fd = stop_pipe[0];

    for (;;) {
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);

        FD_SET(stop_fd, &rfds);
        fd_max = stop_fd;

        if (virtio_console && virtio_console_can_write_data(virtio_console)) {
            stdin_fd = (int)(intptr_t)console->opaque;
            FD_SET(stdin_fd, &rfds);
            fd_max = std::max(stdin_fd, fd_max);

#if 0
            if (s->resize_pending) {
                int width, height;
                console_get_size(s, &width, &height);
                virtio_console_resize_event(virtio_console, width, height);
                s->resize_pending = FALSE;
            }
#endif
        }
        if (ethernet_device) {
            ethernet_device->select_fill(ethernet_device, &fd_max, &rfds, &wfds, &efds, &delay);
        }
        tv.tv_sec = delay / 1000;
        tv.tv_usec = (delay % 1000) * 1000;
        int ret = select(fd_max + 1, &rfds, &wfds, &efds, &tv);
        if (FD_ISSET(stop_fd, &rfds)) {
            close(stop_fd);
            return;
        }

        if (ethernet_device) {
            ethernet_device->select_poll(ethernet_device, &rfds, &wfds, &efds, ret);
        }

        if (virtio_console && FD_ISSET(stdin_fd, &rfds)) {
            uint8_t buf[128];
            int ret, len;
            len = virtio_console_get_write_len(virtio_console);
            len = min_int(len, sizeof(buf));
            ret = console->read_data(console->opaque, buf, len);
            if (ret > 0) {
                virtio_console_write_data(virtio_console, buf, ret);
            }
        }
    }
}

void *VirtioDevices::process_io_thread(void *opaque)
{
    ((VirtioDevices *)opaque)->process_io();
    return NULL;
}

void VirtioDevices::start()
{
    printf("VirtioDevices::start\r\n");
    // TODO this only supports one virtio_block device, but the API makes it appear that multiple are supported
    VIRTIODevice *ps[4];
    int n = 0;
#define ADD_DEVICE(s) if (s) ps[n++] = s
    ADD_DEVICE(virtio_net);
    ADD_DEVICE(virtio_entropy);
    ADD_DEVICE(virtio_block);
    ADD_DEVICE(virtio_console);
#undef ADD_DEVICE
    virtio_start_pending_notify_thread(n, ps);

    pipe(stop_pipe);
    fcntl(stop_pipe[1], F_SETFL, O_NONBLOCK);
    pthread_create(&io_thread, NULL, &process_io_thread, this);
    pthread_setname_np(io_thread, "VirtIO I/O");
}

void VirtioDevices::stop()
{
    virtio_stop_pending_notify_thread();
    char dummy = 'X';
    write(stop_pipe[1], &dummy, sizeof(dummy));
    close(stop_pipe[1]);
}

void VirtioDevices::join()
{
    virtio_join_pending_notify_thread();
    pthread_join(io_thread, NULL);
}

void VirtioDevices::reset()
{
#define RESET_DEVICE(s) if (s) virtio_reset(s)
    RESET_DEVICE(virtio_net);
    RESET_DEVICE(virtio_entropy);
    RESET_DEVICE(virtio_block);
    RESET_DEVICE(virtio_console);
#undef RESET_DEVICE
}
