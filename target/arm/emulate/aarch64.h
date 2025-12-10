/*
 * ARM AARCH64 Fallback Emulation.
 *
 * Copyright (c) 2025 Visual Ehrmanntraut (VisualEhrmanntraut).
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

#ifndef TARGET_ARM_EMULATE_AARCH64_H
#define TARGET_ARM_EMULATE_AARCH64_H

#include "qemu/osdep.h"

typedef uint64_t (*ArmAarch64FallbackEmuGetReg)(CPUState *cpu, int rt);
typedef void (*ArmAarch64FallbackEmuSetReg)(CPUState *cpu, int rt,
                                            uint64_t val);

bool arm_aarch64_fallback_emu_single(CPUState *cpu,
                                     ArmAarch64FallbackEmuGetReg get_reg,
                                     ArmAarch64FallbackEmuSetReg set_reg);
#endif /* TARGET_ARM_EMULATE_AARCH64_H */
