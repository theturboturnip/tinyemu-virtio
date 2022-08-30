#pragma once

#include <string.h>
#include <queue>
#include <mutex>
#include <semaphore.h>
#include <pthread.h>
#include <termios.h>

#include "virtiodevices.h"

// The SiFive test finisher provides 16 bits for an exit code, unsigned, so we
// use negative values for our own special purposes internally.
#define EXIT_CODE_RESET -1

#define VD_READ_ADDR  0x0000
#define VD_FLIT_SIZE  0x0008
#define VD_BURST_CNT  0x000c
#define VD_READ_DATA  0x0040
#define VD_READ_DATA_LO  0x0040
#define VD_READ_DATA_HI  0x0044
#define VD_WRITE_ADDR 0x1000
#define VD_WRITE_BYEN 0x1008
#define VD_WRITE_DATA 0x1040
#define VD_SEND_RESP  0x2000
#define VD_REQ_ID     0x2004
#define VD_IS_WRITE   0x2006
#define VD_REQ_LEVEL  0x2007
#define VD_ENABLE     0x2008

struct Rom {
  uint64_t base;
  uint64_t limit;
  uint64_t *data;
};

struct virtual_device_request {
  uint64_t write_data;
  uint64_t response_data;
  uint32_t read_address;
  uint32_t write_address;
  uint32_t time_stamp;
  uint16_t request_id;
  uint8_t request_level;
  uint8_t request_is_read;
  uint8_t flit_size;
  uint8_t byte_enable;
};

class DmaManager;

class FPGA_io;
class FPGA {
    sem_t sem_misc_response;
    FPGA_io *io;
    //FPGA_RequestProxy *request;
    Rom rom;
    VirtioDevices virtio_devices;
    uint32_t misc_rsp_data;
    //uint32_t last_addr;
    int ctrla_seen;
    uint8_t *pcis_rsp_data; // 64-bytes?
    uint64_t tohost_addr;
    uint64_t fromhost_addr;
    uint64_t sifive_test_addr;
    uint64_t htif_enabled;
    uint64_t uart_enabled;
    int exit_code;

    std::mutex misc_request_mutex;
    std::mutex stdin_mutex;
    std::queue<uint8_t> stdin_queue;
    int stop_stdin_pipe[2];
    pthread_t stdin_thread;
    int virtio_stdio_pipe[2];
    static struct termios orig_stdin_termios;
    static struct termios orig_stdout_termios;
    static bool done_termios;

    friend class FPGA_io;
public:
    FPGA(int id, const Rom &rom, const char *tun_iface);
    virtual ~FPGA();

    void wait_misc_response();

    //void map_pcis_dma();
    //void unmap_pcis_dma();
    void open_dma();
    void close_dma();
    //void ddr_read(uint32_t addr, uint8_t * data);
    //void ddr_write(uint32_t addr, const uint8_t * data, uint64_t wstrb = 0xFFFFFFFFFFFFFFFFul);
    //void ddr_write(uint32_t start_addr, const uint32_t *data, size_t num_bytes);
    void dma_read(uint32_t addr, uint8_t * data, size_t num_bytes);
    void dma_write(uint32_t addr, uint8_t *data, size_t num_bytes);

    void irq_set_levels(uint32_t w1s);
    void irq_clear_levels(uint32_t w1c);
    int read_irq_status ();

    void enqueue_stdin(char *buf, size_t num_chars);
    int dequeue_stdin(uint8_t *chp);

    VirtioDevices &get_virtio_devices() { return virtio_devices; }
    void start_io();
    void stop_io(int code);
    int join_io();

    void set_htif_base_addr(uint64_t baseaddr);
    void set_tohost_addr(uint64_t addr);
    void set_fromhost_addr(uint64_t addr);
    void set_htif_enabled(bool enabled);
    void set_uart_enabled(bool enabled);
    
    bool emulated_mmio_has_request();
    void emulated_mmio_respond();

 private:
    void process_stdin();
    static void *process_stdin_thread(void *opaque);
    static void reset_termios();
    void sbcs_wait();
    
};
