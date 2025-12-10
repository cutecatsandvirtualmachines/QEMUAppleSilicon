/*
 * ChefKiss Kernel Patches.
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

#ifndef HW_ARM_APPLE_SILICON_KERNEL_PATCHES_H
#define HW_ARM_APPLE_SILICON_KERNEL_PATCHES_H

#include "hw/arm/apple-silicon/boot.h"

void ck_patch_kernel(MachoHeader64 *hdr);

#endif /* HW_ARM_APPLE_SILICON_KERNEL_PATCHES_H */
