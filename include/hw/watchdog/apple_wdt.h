#ifndef HW_WATCHDOG_APPLE_WDT_H
#define HW_WATCHDOG_APPLE_WDT_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dt.h"
#include "hw/sysbus.h"

SysBusDevice *apple_wdt_from_node(AppleDTNode *node);

#endif /* HW_WATCHDOG_APPLE_WDT_H */
