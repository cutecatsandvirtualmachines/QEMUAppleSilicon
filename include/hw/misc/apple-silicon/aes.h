#ifndef HW_MISC_APPLE_SILICON_AES_H
#define HW_MISC_APPLE_SILICON_AES_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dt.h"
#include "hw/sysbus.h"

#define TYPE_APPLE_AES "apple-aes"
SysBusDevice *apple_aes_create(AppleDTNode *node, uint32_t board_id);

#endif /* HW_MISC_APPLE_SILICON_AES_H */
