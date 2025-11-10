/*
 * Apple A7IOP Base.
 *
 * Copyright (c) 2023-2025 Visual Ehrmanntraut (VisualEhrmanntraut).
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

#ifndef HW_MISC_APPLE_SILICON_A7IOP_BASE_H
#define HW_MISC_APPLE_SILICON_A7IOP_BASE_H

#include "qemu/osdep.h"

#define APPLE_A7IOP_SEP_CPU_IRQ "apple-a7iop-sep-cpu-irq"
#define APPLE_A7IOP_IOP_IRQ "apple-a7iop-iop-irq"
#define APPLE_A7IOP_SEP_GPIO_MAILBOX "a7iop-sep-gpio-mailbox"
#define APPLE_A7IOP_SEP_GPIO_TIMER0 "a7iop-sep-gpio-timer0"
#define APPLE_A7IOP_SEP_GPIO_TIMER1 "a7iop-sep-gpio-timer1"

typedef enum {
    APPLE_A7IOP_V2 = 0,
    APPLE_A7IOP_V4,
} AppleA7IOPVersion;

enum {
    APPLE_A7IOP_IRQ_IOP_NONEMPTY = 0,
    APPLE_A7IOP_IRQ_IOP_EMPTY,
    APPLE_A7IOP_IRQ_AP_NONEMPTY,
    APPLE_A7IOP_IRQ_AP_EMPTY,
    APPLE_A7IOP_IRQ_MAX,
};

#endif /* HW_MISC_APPLE_SILICON_A7IOP_BASE_H */
