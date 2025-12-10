#ifndef HW_BLOCK_APPLE_SILICON_ANS_H
#define HW_BLOCK_APPLE_SILICON_ANS_H

#include "hw/arm/apple-silicon/dt.h"
#include "hw/misc/apple-silicon/a7iop/base.h"
#include "hw/pci/pci.h"
#include "hw/sysbus.h"

SysBusDevice *apple_ans_from_node(AppleDTNode *node, AppleA7IOPVersion version,
                                  PCIBus *pci_bus);

#endif /* HW_BLOCK_APPLE_SILICON_ANS_H */
