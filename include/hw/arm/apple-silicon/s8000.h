/*
 * Apple S8000 SoC (iPhone 6s Plus).
 *
 * Copyright (c) 2023-2025 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2023-2025 Christian Inci (chris-pcguy).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_ARM_APPLE_SILICON_S8000_H
#define HW_ARM_APPLE_SILICON_S8000_H

#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "hw/arm/apple-silicon/a9.h"
#include "hw/arm/apple-silicon/boot.h"
#include "hw/boards.h"
#include "hw/cpu/cluster.h"
#include "hw/sysbus.h"
#include "hw/usb/tcp-usb.h"
#include "system/kvm.h"

#define TYPE_S8000 "s8000"

#define TYPE_S8000_MACHINE MACHINE_TYPE_NAME(TYPE_S8000)

#define S8000_MACHINE(obj) \
    OBJECT_CHECK(S8000MachineState, (obj), TYPE_S8000_MACHINE)

typedef struct {
    MachineClass parent;
} S8000MachineClass;

typedef enum {
    kBootModeAuto = 0,
    kBootModeManual,
    kBootModeEnterRecovery,
    kBootModeExitRecovery,
} AppleBootMode;

typedef struct {
    MachineState parent;
    hwaddr armio_base;
    hwaddr armio_size;

    unsigned long dram_size;
    AppleA9State *cpus[A9_MAX_CPU];
    CPUClusterState cluster;
    SysBusDevice *aic;
    SysBusDevice *sep;
    MemoryRegion *sys_mem;
    MachoHeader64 *kernel;
    MachoHeader64 *secure_monitor;
    uint8_t *trustcache;
    char *securerom;
    gsize securerom_size;
    AppleDTNode *device_tree;
    AppleBootInfo boot_info;
    AppleVideoArgs video_args;
    char *trustcache_filename;
    char *ticket_filename;
    char *sep_rom_filename;
    char *sep_fw_filename;
    char *securerom_filename;
    AppleBootMode boot_mode;
    uint32_t build_version;
    uint64_t ecid;
    Notifier init_done_notifier;
    hwaddr panic_base;
    hwaddr panic_size;
    char pmgr_reg[0x100000];
    bool kaslr_off;
    bool force_dfu;
    uint32_t board_id;
    USBTCPRemoteConnType usb_conn_type;
    char *usb_conn_addr;
    uint16_t usb_conn_port;
} S8000MachineState;

#endif /* HW_ARM_APPLE_SILICON_S8000_H */
