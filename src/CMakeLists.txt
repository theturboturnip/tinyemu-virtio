

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

include_directories(.)
include_directories(slirp)

# optimization -O2, warnings -Wall, debug mode -g, and some extra #defines that probably aren't needed (e.g. clang always defines _GNU_SOURCE) - likely a holdover from the original tinyemu project
set(CMAKE_C_FLAGS "-O2 -Wall -g -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE ${CMAKE_C_FLAGS}" )
# enable SLIRP by default
set(CMAKE_C_FLAGS "-DCONFIG_SLIRP ${CMAKE_C_FLAGS}")

if (EXISTS "/usr/bin/curl-config")
set(CMAKE_C_FLAGS "-DCONFIG_FS_NET ${CMAKE_C_FLAGS}")
set(FS_NET_SOURCES block_net.c fs_net.c fs_wget.c fs_wget.h)
set(FS_NET_LIBRARIES -lcurl -lssl -lcrypto)
endif()

# Give C++ the same #defines and options as C
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")
# *always* link libstdc++, compilation fails on our CI otherwise.
set(CMAKE_EXE_LINKER_FLAGS "-lstdc++")

set(TINYEMU_SOURCES
  slirp/bootp.c
  slirp/bootp.h
  slirp/cksum.c
  slirp/debug.h
  slirp/if.c
  slirp/if.h
  slirp/ip.h
  slirp/ip_icmp.c
  slirp/ip_icmp.h
  slirp/ip_input.c
  slirp/ip_output.c
  slirp/libslirp.h
  slirp/main.h
  slirp/mbuf.c
  slirp/mbuf.h
  slirp/misc.c
  slirp/misc.h
  slirp/sbuf.c
  slirp/sbuf.h
  slirp/slirp.c
  slirp/slirp.h
  slirp/slirp_config.h
  slirp/socket.c
  slirp/socket.h
  slirp/tcp.h
  slirp/tcp_input.c
  slirp/tcp_output.c
  slirp/tcp_subr.c
  slirp/tcp_timer.c
  slirp/tcp_timer.h
  slirp/tcp_var.h
  slirp/tcpip.h
  slirp/tftp.h
  slirp/udp.c
  slirp/udp.h
  iocap/librust_caps_c_panic.cpp
  # Don't override our main!
  #build_filelist.c
  cutils.c
  cutils.h
  fs.c
  fs.h
  #fs_disk.c
  #fs_utils.c
  #fs_utils.h
  iomem.c
  iomem.h
  list.h
  pci.c
  pci.h
  temu.c
  ${FS_NET_SOURCES}
  util.cpp
  util.h
  virtio.c
  virtio.h
  virtiodevices.cpp
  virtiodevices.h
  loadelf.cpp
  loadelf.h
  )


if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
set(IOCAP_LIB ${CMAKE_SOURCE_DIR}/src/iocap/x86_64-unknown-none/librust_caps_c.a)
include_directories(iocap/x86_64-unknown-none)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
set(IOCAP_LIB ${CMAKE_SOURCE_DIR}/src/iocap/aarch64-unknown-none/librust_caps_c.a)
include_directories(iocap/aarch64-unknown-none)
else()
message(FATAL_ERROR "cannot compile with iocaplib on this platform")
endif()

# The iocap library depends on someone else defining an external function ccap_panic_write_utf8.
# tinyemu defines this.
# We need to tell CMake that iocap depends on tinyemu, otherwise we get link errors.
# CMake will handle the circular dependency.
add_library(iocap STATIC IMPORTED)
set_property(TARGET iocap PROPERTY IMPORTED_LOCATION ${IOCAP_LIB})
set_target_properties(iocap PROPERTIES PREFIX lib)
target_link_libraries(iocap INTERFACE tinyemu)

add_library(tinyemu ${TINYEMU_SOURCES})
target_link_libraries(tinyemu ${SDL_LIBRARIES} ${FS_NET_LIBRARIES} iocap)

add_executable(fmem_virtio_host
  fpga.h
  fpga.cpp
  main.cpp
  )
target_link_libraries(fmem_virtio_host tinyemu pthread elf)
