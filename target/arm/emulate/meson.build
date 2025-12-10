arm_emulate_ss = ss.source_set()
arm_emulate_ss.add(when: 'TARGET_AARCH64', if_true: files('aarch64.c'))
arm_system_ss.add_all(when: 'CONFIG_KVM', if_true: arm_emulate_ss)
arm_system_ss.add_all(when: 'CONFIG_HVF', if_true: arm_emulate_ss)
