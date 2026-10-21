/*
 * Copyright © 2026 libratbag contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * E-YOOSO X-41 Pro (Redragon OEM, Holtek VID 0x04d9 / 0x36b7:0xfd15) driver.
 *
 * The device is configured over HID *feature reports* on vendor usage page
 * 0xffa0. The wire format was recovered from live capture of the vendor tool
 * (RDCfg.exe) -- see PROTOCOL-X41PRO.md for the full byte-level spec.
 *
 * Report IDs are report *types* (not request/response):
 *   0x02 (15B)  control: begin/commit, poll rate
 *   0x03 (63B)  button + LED config
 *   0x04 (255B) profile block (DPI + button map)
 *   0x05/0x06   macro key storage
 *
 * buf[0]=report id, buf[1]=family (0xf1 set / 0xf3 config / 0xf5 control),
 * buf[2..3]=address for config blocks.
 */

#include "config.h"
#include "libratbag-enums.h"
#include "libratbag-hidraw.h"
#include "libratbag-private.h"
#include "libratbag-util.h"

#include <stdint.h>
#include <string.h>
#include <linux/input.h>

/* ---- report ids / sizes (from report descriptor) ---- */
#define RID_CMD		0x02	/* 15-byte control */
#define RID_CFG		0x03	/* 63-byte button + LED */
#define RID_PROFILE	0x04	/* 255-byte profile block */
#define CMD_SIZE	16
#define CFG_SIZE	64
#define PROFILE_SIZE	256

/* ---- family (buf[1]) ---- */
#define FAM_SET		0xf1
#define FAM_CFG		0xf3
#define FAM_CTRL	0xf5

/* ---- control opcodes (buf[2], family 0xf5) ---- */
#define CTRL_BEGIN	0x00
#define CTRL_COMMIT	0x01

/* ---- button action codes (wire) ---- */
#define ACT_MOUSE(n)	(0x80 | (n))	/* n = 1..5 */
#define ACT_DBLCLICK	0x89
#define ACT_DPI_DOWN	0x8a
#define ACT_DPI_UP	0x99
#define ACT_MACRO	0x90

/* ---- profile block layout ---- */
#define PROF_ADDR(p)	prof_addr[p]
#define OFF_DPI		12
#define DPI_SIZE	6
#define OFF_BTNCNT	66
#define OFF_BTNREC	68
#define BTNREC_SIZE	4

/* 5 profile base addresses (report 0x04 buf[2..3]) */
static const uint16_t prof_addr[5] = { 0x40, 0x100, 0x1b0, 0x260, 0x310 };

#define NUM_PROFILES	5
#define NUM_RESOLUTIONS	5
#define NUM_BUTTONS	11
#define NUM_LEDS	2

/* report rates (Hz); wire value is one-hot bit index */
static unsigned int RATES[] = { 125, 250, 500, 1000, 2000 };
/* default report rate per profile (RDCfg.exe writes 04,01,02,08,10) */
static unsigned int DEFAULT_HZ[] = { 500, 125, 250, 1000, 2000 };
/* raw DPI stage x/y values seen on the wire (TODO: scale to real DPI) */
static unsigned int DPIS[] = { 5, 10, 20, 30, 40 };

struct redragon_data {
	uint8_t active;
	/* default wire records for each button slot (from RDCfg.exe capture) */
	uint8_t btn_rec[NUM_BUTTONS][4];
};

/*
 * Default button records (profile 0 from the live capture). Used verbatim for
 * buttons the user hasn't modified so that Apply is idempotent -- otherwise a
 * write-only driver would clobber macros / dpi-up with wrong defaults.
 */
static const uint8_t BTN_DEFAULT[NUM_BUTTONS][4] = {
	{ 0x81, 0x00, 0x00, 0x00 },	/* 0 left      */
	{ 0x82, 0x00, 0x00, 0x00 },	/* 1 right     */
	{ 0x83, 0x00, 0x00, 0x00 },	/* 2 wheel-click */
	{ 0x85, 0x00, 0x00, 0x00 },	/* 3 next      */
	{ 0x84, 0x00, 0x00, 0x00 },	/* 4 prev      */
	{ 0x99, 0x81, 0x03, 0x0a },	/* 5 dpi-up    */
	{ 0x8a, 0x00, 0x00, 0x00 },	/* 6 dpi-down  */
	{ 0x89, 0x00, 0x00, 0x00 },	/* 7 double-click */
	{ 0x90, 0x00, 0xe2, 0x00 },	/* 8 macro1    */
	{ 0x90, 0x00, 0xe0, 0x00 },	/* 9 macro2    */
	{ 0x90, 0x00, 0xe1, 0x00 },	/* 10 macro3   */
};

static int write_report(struct ratbag_device *device, uint8_t id, uint8_t *buf, size_t len);

/*
 * Global button / hardware config (report 0x03, opcode 0x20). RDCfg.exe always
 * writes this once before the profile blocks; omitting it leaves the buttons
 * non-functional. Static default captured from RDCfg.exe.
 */
static const uint8_t BTN_GLOBAL_CFG[64] = {
	0x03, 0xf3, 0x20, 0x00, 0x20, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x80,
	0x03, 0xc0, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x1f, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static int
write_global_cfg(struct ratbag_device *device)
{
	uint8_t b[CFG_SIZE];
	memcpy(b, BTN_GLOBAL_CFG, CFG_SIZE);
	return write_report(device, RID_CFG, b, CFG_SIZE);
}

/* ------------------------------------------------------------------ */

static int
redragon_test_hidraw(struct ratbag_device *device)
{
	/* config lives on the vendor usage page 0xffa0 */
	return ratbag_hidraw_has_vendor_page(device) ? 1 : 0;
}

static int
write_report(struct ratbag_device *device, uint8_t id, uint8_t *buf, size_t len)
{
	buf[0] = id;
	int rc = ratbag_hidraw_set_feature_report(device, id, buf, len);
	if (rc < 0)
		log_error(device->ratbag, "write report 0x%02x failed: %d\n", id, rc);
	return rc < 0 ? rc : 0;
}

static int
ctrl(struct ratbag_device *device, uint8_t op)
{
	uint8_t b[CMD_SIZE] = {0};
	b[1] = FAM_CTRL;
	b[2] = op;
	return write_report(device, RID_CMD, b, CMD_SIZE);
}

static int
set_poll_rate(struct ratbag_device *device, unsigned int rate)
{
	uint8_t b[CMD_SIZE] = {0};
	b[1] = FAM_SET;
	b[2] = 0x02;
	b[3] = 0x01;	/* one-hot */
	for (size_t i = 0; i < ARRAY_LENGTH(RATES); i++)
		if (RATES[i] == rate) {
			b[3] = (uint8_t)(1 << i);
			break;
		}
	return write_report(device, RID_CMD, b, CMD_SIZE);
}

static int
set_led(struct ratbag_device *device, struct ratbag_led *led)
{
	uint8_t b[CFG_SIZE] = {0};
	b[1] = FAM_CFG;
	b[2] = 0x46;
	b[3] = 0x04;
	b[4] = 0x32;
	/* 5 LED records of 8 bytes at offset 10: [80 R G B 02 04 01 02] */
	for (int i = 0; i < 5; i++) {
		int o = 10 + i * 8;
		b[o + 0] = 0x80;
		b[o + 1] = led->color.red;
		b[o + 2] = led->color.green;
		b[o + 3] = led->color.blue;
		b[o + 4] = 0x02;
		b[o + 5] = 0x04;
		b[o + 6] = 0x01;
		b[o + 7] = 0x02;
	}
	return write_report(device, RID_CFG, b, CFG_SIZE);
}

/* map a ratbag action to the wire action code (+ macro id) */
static uint8_t
action_code(const struct ratbag_button_action *a, uint8_t *macro_id)
{
	*macro_id = 0;
	switch (a->type) {
	case RATBAG_BUTTON_ACTION_TYPE_BUTTON:
		return ACT_MOUSE(a->action.button ? a->action.button : 1);
	case RATBAG_BUTTON_ACTION_TYPE_SPECIAL:
		switch (a->action.special) {
		case RATBAG_BUTTON_ACTION_SPECIAL_DOUBLECLICK:
			return ACT_DBLCLICK;
		case RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_UP:
			return ACT_DPI_UP;
		case RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_DOWN:
			return ACT_DPI_DOWN;
		default:
			return ACT_MOUSE(1);
		}
	case RATBAG_BUTTON_ACTION_TYPE_MACRO:
		*macro_id = 0xe0;	/* TODO: allocate macro id + upload keys */
		return ACT_MACRO;
	default:
		return ACT_MOUSE(1);
	}
}

static int
write_profile(struct ratbag_device *device, struct ratbag_profile *profile)
{
	uint8_t b[PROFILE_SIZE] = {0};
	unsigned int p = profile->index;

	b[1] = FAM_CFG;
	b[2] = prof_addr[p] & 0xff;
	b[3] = prof_addr[p] >> 8;
	b[4] = 0xaf;	/* data length */
	b[5] = 0x00;
	b[8] = NUM_RESOLUTIONS & 0xff;
	b[9] = NUM_RESOLUTIONS >> 8;
	b[10] = p & 0xff;
	b[11] = p >> 8;

	/* DPI stages */
	struct ratbag_resolution *res;
	int i = 0;
	ratbag_profile_for_each_resolution(profile, res) {
		if (i >= NUM_RESOLUTIONS)
			break;
		int o = OFF_DPI + i * DPI_SIZE;
		b[o + 0] = 0x01;
		b[o + 1] = res->dpi_x & 0xff;
		b[o + 2] = res->dpi_x >> 8;
		b[o + 3] = res->dpi_y & 0xff;
		b[o + 4] = res->dpi_y >> 8;
		b[o + 5] = 0x00;
		i++;
	}

	/* button map */
	b[OFF_BTNCNT] = NUM_BUTTONS;
	struct redragon_data *d = ratbag_get_drv_data(device);
	struct ratbag_button *btn;
	i = 0;
	ratbag_profile_for_each_button(profile, btn) {
		if (i >= NUM_BUTTONS)
			break;
		int o = OFF_BTNREC + i * BTNREC_SIZE;
		if (btn->dirty) {
			uint8_t mid = 0;
			uint8_t act = action_code(&btn->action, &mid);
			b[o + 0] = act;
			b[o + 1] = 0x00;
			b[o + 2] = mid;
			b[o + 3] = 0x00;
			memcpy(d->btn_rec[i], &b[o], 4);
		} else {
			/* preserve the real on-device record (idempotent apply) */
			memcpy(&b[o], d->btn_rec[i], 4);
		}
		i++;
	}
	/* extra + scroll records (static defaults from capture) */
	b[112] = ACT_DPI_DOWN + 0x03;	/* 0x8d */
	b[116] = 0x8b;			/* scroll-up */
	b[120] = 0x8c;			/* scroll-down */
	b[124] = 0xff; b[125] = 0xff; b[126] = 0xff; b[127] = 0xff;

	return write_report(device, RID_PROFILE, b, PROFILE_SIZE);
}

/* ------------------------------------------------------------------ */

static int
redragon_commit(struct ratbag_device *device)
{
	struct ratbag_profile *profile;

	ctrl(device, CTRL_BEGIN);
	write_global_cfg(device);

	/* LED config */
	list_for_each(profile, &device->profiles, link) {
		struct ratbag_led *led;
		ratbag_profile_for_each_led(profile, led) {
			if (!led->dirty)
				continue;
			set_led(device, led);
		}
	}

	/* profile blocks (matches RDCfg.exe: write ALL profiles) */
	list_for_each(profile, &device->profiles, link) {
		write_profile(device, profile);
	}

	/* then poll rates (matches RDCfg.exe: write ALL profiles' rates) */
	list_for_each(profile, &device->profiles, link) {
		set_poll_rate(device, profile->hz);
	}

	ctrl(device, CTRL_COMMIT);
	return 0;
}

static int
redragon_set_active_profile(struct ratbag_device *device, unsigned int index)
{
	struct redragon_data *d = ratbag_get_drv_data(device);
	d->active = (uint8_t)index;
	ctrl(device, CTRL_COMMIT);
	return 0;
}

static int
redragon_probe(struct ratbag_device *device)
{
	struct redragon_data *d;

	if (ratbag_find_hidraw(device, redragon_test_hidraw))
		return -ENODEV;

	d = zalloc(sizeof(*d));
	if (!d)
		return -ENOMEM;
	ratbag_set_drv_data(device, d);
	memcpy(d->btn_rec, BTN_DEFAULT, sizeof(d->btn_rec));

	/*
	 * Write-capable for now: seed from the vendor defaults and let the user
	 * configure via Piper. TODO: read the current config back (query/report
	 * 0x04 get) so Piper shows the saved state.
	 */
	ratbag_device_init_profiles(device, NUM_PROFILES, NUM_RESOLUTIONS,
				   NUM_BUTTONS, NUM_LEDS);

	struct ratbag_profile *profile;
	ratbag_device_for_each_profile(device, profile) {
		profile->is_active = (profile->index == d->active);
		profile->hz = DEFAULT_HZ[profile->index % ARRAY_LENGTH(DEFAULT_HZ)];
		ratbag_profile_set_cap(profile, RATBAG_PROFILE_CAP_WRITE_ONLY);
		ratbag_profile_set_report_rate_list(profile, RATES, ARRAY_LENGTH(RATES));

		struct ratbag_resolution *res;
		ratbag_profile_for_each_resolution(profile, res) {
			unsigned int v = DPIS[res->index < ARRAY_LENGTH(DPIS)
					      ? res->index : ARRAY_LENGTH(DPIS) - 1];
			ratbag_resolution_set_dpi_list(res, DPIS, ARRAY_LENGTH(DPIS));
			ratbag_resolution_set_cap(res, RATBAG_RESOLUTION_CAP_SEPARATE_XY_RESOLUTION);
			res->dpi_x = res->dpi_y = v;
			res->is_active = (res->index == 0);
			res->is_default = (res->index == 0);
		}

		struct ratbag_button *btn;
		ratbag_profile_for_each_button(profile, btn) {
			ratbag_button_enable_action_type(btn, RATBAG_BUTTON_ACTION_TYPE_BUTTON);
			ratbag_button_enable_action_type(btn, RATBAG_BUTTON_ACTION_TYPE_SPECIAL);
			ratbag_button_enable_action_type(btn, RATBAG_BUTTON_ACTION_TYPE_KEY);
			ratbag_button_enable_action_type(btn, RATBAG_BUTTON_ACTION_TYPE_MACRO);
			ratbag_button_enable_action_type(btn, RATBAG_BUTTON_ACTION_TYPE_NONE);
			/* default map from the capture */
			btn->action.type = RATBAG_BUTTON_ACTION_TYPE_BUTTON;
			switch (btn->index) {
			case 0: btn->action.action.button = 1; break;
			case 1: btn->action.action.button = 2; break;
			case 2: btn->action.action.button = 3; break;
			case 3: btn->action.action.button = 5; break;	/* next */
			case 4: btn->action.action.button = 4; break;	/* prev */
			case 5: btn->action.type = RATBAG_BUTTON_ACTION_TYPE_SPECIAL;
				btn->action.action.special = RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_UP; break;
			case 6: btn->action.type = RATBAG_BUTTON_ACTION_TYPE_SPECIAL;
				btn->action.action.special = RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_DOWN; break;
			case 7: btn->action.type = RATBAG_BUTTON_ACTION_TYPE_SPECIAL;
				btn->action.action.special = RATBAG_BUTTON_ACTION_SPECIAL_DOUBLECLICK; break;
			default:
				/* macro1/2/3: run a device-side macro; placeholder key
				 * for display (real key sequence lives in report 0x05/0x06) */
				ratbag_button_macro_new_from_keycode(btn,
						KEY_F13 + (btn->index - 8), 0);
				break;
			}
		}

		struct ratbag_led *led;
		ratbag_profile_for_each_led(profile, led) {
			led->mode = RATBAG_LED_ON;
			led->color.red = led->color.green = led->color.blue = 0xff;
			led->colordepth = RATBAG_LED_COLORDEPTH_RGB_888;
			led->brightness = 255;
			led->ms = 1000;
			ratbag_led_set_mode_capability(led, RATBAG_LED_OFF);
			ratbag_led_set_mode_capability(led, RATBAG_LED_ON);
			ratbag_led_set_mode_capability(led, RATBAG_LED_BREATHING);
			ratbag_led_set_mode_capability(led, RATBAG_LED_CYCLE);
		}
	}

	return 0;
}

static void
redragon_remove(struct ratbag_device *device)
{
	ratbag_close_hidraw(device);
	free(ratbag_get_drv_data(device));
	ratbag_set_drv_data(device, NULL);
}

struct ratbag_driver redragon_driver = {
	.name = "E-YOOSO X-41 Pro (Redragon)",
	.id = "redragon",
	.probe = redragon_probe,
	.remove = redragon_remove,
	.commit = redragon_commit,
	.set_active_profile = redragon_set_active_profile,
};
