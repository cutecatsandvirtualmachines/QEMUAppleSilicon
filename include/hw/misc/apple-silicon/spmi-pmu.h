#ifndef HW_MISC_APPLE_SILICON_SPMI_PMU_H
#define HW_MISC_APPLE_SILICON_SPMI_PMU_H

#include "hw/arm/apple-silicon/dt.h"

DeviceState *apple_spmi_pmu_from_node(AppleDTNode *node);
#endif /* HW_MISC_APPLE_SILICON_SPMI_PMU_H */
