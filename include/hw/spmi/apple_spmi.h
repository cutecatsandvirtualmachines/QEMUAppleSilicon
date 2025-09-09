/*
 * Apple System Management Power Interface.
 *
 * Copyright (c) 2024-2025 Visual Ehrmanntraut (VisualEhrmanntraut).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef HW_SPMI_APPLE_SPMI_H
#define HW_SPMI_APPLE_SPMI_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dt.h"
#include "hw/spmi/spmi.h"
#include "hw/sysbus.h"
#include "qemu/fifo32.h"
#include "qemu/queue.h"
#include "qom/object.h"

#define TYPE_APPLE_SPMI "apple.spmi"
OBJECT_DECLARE_TYPE(AppleSPMIState, AppleSPMIClass, APPLE_SPMI)
#define APPLE_SPMI_MMIO_SIZE (0x4000)

typedef struct AppleSPMIClass {
    /*< private >*/
    SysBusDeviceClass parent_class;
    ResettablePhases parent_phases;

    /*< public >*/
} AppleSPMIClass;

struct AppleSPMIState {
    SysBusDevice parent_obj;
    MemoryRegion container;
    MemoryRegion iomems[4];
    SPMIBus *bus;
    qemu_irq irq;
    qemu_irq resp_irq;
    Fifo32 resp_fifo;
    uint32_t control_reg[0x100 / sizeof(uint32_t)];
    uint32_t queue_reg[0x100 / sizeof(uint32_t)];
    uint32_t fault_reg[0x100 / sizeof(uint32_t)];
    uint32_t fault_counter_reg[0x64 / sizeof(uint32_t)];
    uint32_t resp_intr_index;
    uint32_t reg_vers;
    uint32_t *data;
    uint32_t data_length;
    uint32_t data_filled;
    uint32_t command;
};

SysBusDevice *apple_spmi_from_node(AppleDTNode *node);

#endif /* HW_SPMI_APPLE_SPMI_H */
