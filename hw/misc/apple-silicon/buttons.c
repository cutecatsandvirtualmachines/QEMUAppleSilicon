/*
 * Apple iPhone 11 Buttons
 *
 * Copyright (c) 2025 Christian Inci (chris-pcguy).
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

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dt.h"
#include "hw/misc/apple-silicon/a7iop/rtkit.h"
#include "hw/misc/apple-silicon/buttons.h"
#include "hw/misc/apple-silicon/smc.h"
#include "hw/qdev-core.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/lockable.h"
#include "ui/input.h"
#include "system/runstate.h"

#if 1
#include "qemu/log.h"
#define DPRINTF(fmt, ...)                    \
    do {                                     \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define DPRINTF(fmt, ...) \
    do {                  \
    } while (0)
#endif

#define TYPE_APPLE_BUTTONS "apple.buttons"
OBJECT_DECLARE_SIMPLE_TYPE(AppleButtonsState, APPLE_BUTTONS)

struct AppleButtonsState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    QemuMutex mutex;
    bool states[SMC_HID_BUTTON_COUNT];
};

static void apple_buttons_handle_event(DeviceState *dev, QemuConsole *src,
                                       InputEvent *evt)
{
    AppleButtonsState *s = APPLE_BUTTONS(dev);
    InputKeyEvent *key = evt->u.key.data;
    int qcode;
    AppleSMCHIDButton button;

    QEMU_LOCK_GUARD(&s->mutex);

    AppleSMCState *smc = APPLE_SMC_IOP(object_property_get_link(
        OBJECT(qdev_get_machine()), "smc", &error_fatal));

    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER, NULL);

    qcode = qemu_input_key_value_to_qcode(key->key);

    DPRINTF("%s: qcode=0x%x/%d, key->down=%d\n", __func__, qcode, qcode,
            key->down);

    switch (qcode) {
    case Q_KEY_CODE_F1:
        button = SMC_HID_BUTTON_FORCE_SHUTDOWN;
        break;
    case Q_KEY_CODE_F2:
        if (key->down) {
            button = SMC_HID_BUTTON_RINGER;
            s->states[button] = !s->states[button];
            apple_smc_send_hid_button(smc, button, s->states[button]);
        }
        return;
    case Q_KEY_CODE_F3:
        button = SMC_HID_BUTTON_VOL_DOWN;
        break;
    case Q_KEY_CODE_F4:
        button = SMC_HID_BUTTON_VOL_UP;
        break;
    case Q_KEY_CODE_F5:
        button = SMC_HID_BUTTON_POWER;
        break;
    case Q_KEY_CODE_F6:
        button = SMC_HID_BUTTON_MENU;
        break;
    case Q_KEY_CODE_F7:
        button = SMC_HID_BUTTON_HELP;
        break;
    case Q_KEY_CODE_F8:
        button = SMC_HID_BUTTON_HELP_DOUBLE;
        break;
    case Q_KEY_CODE_F9:
        button = SMC_HID_BUTTON_HALL_EFFECT_1;
        break;
    case Q_KEY_CODE_F10:
        button = SMC_HID_BUTTON_HALL_EFFECT;
        break;
    default:
        return;
    }

    if (s->states[button] != key->down) {
        s->states[button] = key->down;
        apple_smc_send_hid_button(smc, button, key->down);
    }
}

static uint8_t smc_key_btnR_read(AppleSMCState *s, SMCKey *key,
                                 SMCKeyData *data, void *payload,
                                 uint8_t length)
{
    uint32_t value;
    uint32_t tmpval0;

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    value = ldl_le_p(payload);

    if (data->data == NULL) {
        data->data = g_malloc(key->info.size);
    } else {
        uint32_t *data0 = data->data;
        DPRINTF("%s: data->data: %p ; data0[0]: 0x%08x\n", __func__, data->data,
                data0[0]);
    }

    DPRINTF("%s: key->info.size: 0x%08x ; length: 0x%08x\n", __func__,
            key->info.size, length);
    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value, length);

    switch (value) {
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_btnR_write(AppleSMCState *s, SMCKey *key,
                                  SMCKeyData *data, void *payload,
                                  uint8_t length)
{
    AppleRTKit *rtk;
    uint32_t value;
    KeyResponse r;

    AppleButtonsState *buttons = APPLE_BUTTONS(object_property_get_link(
        OBJECT(qdev_get_machine()), "buttons", &error_fatal));

    if (payload == NULL || length != key->info.size) {
        return kSMCBadArgumentError;
    }

    rtk = APPLE_RTKIT(s);
    value = ldl_le_p(payload);

    // Do not use data->data here, as it only contains the data last written to
    // by the read function (smc_key_gP09_read)

    DPRINTF("%s: value: 0x%08x ; length: 0x%08x\n", __func__, value, length);

    switch (value) {
    default:
        DPRINTF("%s: UNKNOWN VALUE: 0x%08x\n", __func__, value);
        return kSMCBadFuncParameter;
    }
}

SysBusDevice *apple_buttons_create(AppleDTNode *node)
{
    DeviceState *dev;
    AppleButtonsState *s;
    SysBusDevice *sbd;
    AppleDTProp *prop;

    dev = qdev_new(TYPE_APPLE_BUTTONS);
    s = APPLE_BUTTONS(dev);
    sbd = SYS_BUS_DEVICE(dev);

    AppleSMCState *smc = APPLE_SMC_IOP(object_property_get_link(
        OBJECT(qdev_get_machine()), "smc", &error_fatal));
    apple_smc_create_key_func(smc, 'btnR', 4, SMCKeyTypeUInt32,
                              SMC_ATTR_FUNCTION | SMC_ATTR_WRITEABLE |
                                  SMC_ATTR_READABLE | 0x20,
                              smc_key_btnR_read, smc_key_btnR_write);

    qemu_mutex_init(&s->mutex);

    return sbd;
}

static void apple_buttons_qdev_reset_hold(Object *obj, ResetType type)
{
    AppleButtonsState *s = APPLE_BUTTONS(obj);
    QEMU_LOCK_GUARD(&s->mutex);
    memset(s->states, 0, sizeof(s->states));
}

static const QemuInputHandler apple_buttons_handler = {
    .name = "Apple Buttons",
    .mask = INPUT_EVENT_MASK_KEY,
    .event = apple_buttons_handle_event,
};

static void apple_buttons_realize(DeviceState *dev, Error **errp)
{
    QemuInputHandlerState *s =
        qemu_input_handler_register(dev, &apple_buttons_handler);
    qemu_input_handler_activate(s);
    qemu_system_wakeup_enable(QEMU_WAKEUP_REASON_OTHER, true);
}

static void apple_buttons_unrealize(DeviceState *dev)
{
    AppleButtonsState *s = APPLE_BUTTONS(dev);
}

static const VMStateDescription vmstate_apple_buttons = {
    .name = "AppleButtonsState",
    .version_id = 0,
    .minimum_version_id = 0,
    .fields =
        (const VMStateField[]){
            VMSTATE_BOOL_ARRAY(states, AppleButtonsState, SMC_HID_BUTTON_COUNT),
            VMSTATE_END_OF_LIST(),
        }
};

static void apple_buttons_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    rc->phases.hold = apple_buttons_qdev_reset_hold;

    dc->realize = apple_buttons_realize;
    dc->unrealize = apple_buttons_unrealize;
    dc->desc = "Apple Buttons";
    dc->vmsd = &vmstate_apple_buttons;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);
}

static const TypeInfo apple_buttons_types = {
    .name = TYPE_APPLE_BUTTONS,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleButtonsState),
    .class_init = apple_buttons_class_init,
};

static void apple_buttons_init(void)
{
    type_register_static(&apple_buttons_types);
}

type_init(apple_buttons_init);
