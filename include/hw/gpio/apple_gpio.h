/*
 * Apple General-Purpose Input/Output.
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

#ifndef HW_GPIO_APPLE_GPIO_H
#define HW_GPIO_APPLE_GPIO_H

#include "hw/arm/apple-silicon/dt.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_GPIO "apple-gpio"
OBJECT_DECLARE_SIMPLE_TYPE(AppleGPIOState, APPLE_GPIO)

struct AppleGPIOState {
    SysBusDevice parent_obj;
    MemoryRegion *iomem;
    uint32_t pin_count;
    uint32_t irq_group_count;
    qemu_irq *irqs;
    qemu_irq *out;
    uint32_t *gpio_cfg;
    uint32_t int_config_len;
    uint32_t *int_config;
    uint32_t in_len;
    uint32_t *in;
    uint32_t *in_old;
    uint32_t npl;
};

DeviceState *apple_gpio_new(const char *name, uint64_t mmio_size,
                            uint32_t pin_count, uint32_t irq_group_count);
DeviceState *apple_gpio_from_node(AppleDTNode *node);
#endif
