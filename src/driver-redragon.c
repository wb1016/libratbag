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
 * E-YOOSO X-41 Pro (Redragon OEM, Holtek VID 0x04d9) driver.
 *
 * The vendor Windows tool (RDCfg.exe) configures this mouse exclusively over
 * HID *feature reports* on a vendor usage page (0xffa0). The wire protocol was
 * recovered from RDCfg.exe + HidDevice.dll (static RE with r2ghidra); see
 * PROTOCOL-X41PRO.md in the repository root for the full notes.
 *
 * Framing (feature reports):
 *   buf[0]  type   0x02 = host->device command / query request
 *                  0x03 = device->host query response / LED write
 *   buf[1]  family 0xf1 = set value   0xf2 = query   0xf3 = button / LED
 *   buf[2]  opcode / subcommand
 *   buf[3..] payload
 *
 * Report sizes: 16 bytes for query + simple set; 64 bytes for button/LED bulk.
 * Sequencing: 10 ms between a query request and its response, 50 ms between
 * multi-part write chunks.
 *
 * TODO(hardware-validate): byte offsets and opcodes tagged below were recovered
 * statically and must be confirmed against the real device (lsusb -v report
 * descriptor + usbmon/Wine captures). The transport, framing, and data model
 * are solid; per-command payload packing needs a final calibration pass.
 */

#include "config.h"
#include "libratbag-enums.h"
#include "libratbag-hidraw.h"
#include "libratbag-private.h"
#include "libratbag-util.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Wire protocol constants (recovered from RDCfg.exe)                  */
/* ------------------------------------------------------------------ */

#define REDRAGON_REPORT_SIZE		64
#define REDRAGON_QUERY_SIZE		16

/* buf[0]: message type / report id */
#define REDRAGON_TYPE_CMD		0x02	/* host -> device */
#define REDRAGON_TYPE_RESP		0x03	/* device -> host / LED */

/* buf[1]: command family */
#define REDRAGON_FAMILY_SET		0xf1
#define REDRAGON_FAMILY_QUERY		0xf2
#define REDRAGON_FAMILY_BUTTON		0xf3	/* button + LED bulk */

/* Sequencing delays. */
#define REDRAGON_WRITE_CHUNK_DELAY_MS	50
#define REDRAGON_QUERY_DELAY_MS		10

/* Recovered opcodes. TODO(hardware-validate) */
#define REDRAGON_OP_SET_POLL_RATE	0x02	/* family f1 */
#define REDRAGON_OP_QUERY_POLL_RATE	0x32	/* family f2 */
#define REDRAGON_OP_QUERY_LED_BASE	0x49	/* family f2: + index*8 */
#define REDRAGON_OP_QUERY_DPI		0x30	/* family f2 — TODO */
#define REDRAGON_OP_BUTTON_REFRESH	0x48	/* family f3 */
#define REDRAGON_OP_LED_WRITE		0x46	/* family f3 */

/* ------------------------------------------------------------------ */
/* Device capability (from vendor descriptor PRODUCT group)            */
/* ------------------------------------------------------------------ */

#define REDRAGON_NUM_PROFILES		5	/* PROFILE_0..4 */
#define REDRAGON_NUM_RESOLUTIONS	5	/* PRODUCT/DPICount=5 */
#define REDRAGON_NUM_BUTTONS		11	/* PRODUCT/Count=11 */
#define REDRAGON_NUM_LEDS		2	/* PRODUCT/Light=2 */

/*
 * Poll rates (Hz). The vendor stores a small code (Config.ini pollrate=).
 * TODO(hardware-validate): exact code<->Hz mapping.
 */
static unsigned int REDRAGON_REPORT_RATES[] = { 125, 250, 500, 1000 };

/*
 * DPI stages. The vendor descriptor stores raw codes (Default.bin D1..D5).
 * TODO(hardware-validate): raw<->dpi mapping; expose a conventional list for
 * now and encode the list index.
 */
static unsigned int REDRAGON_DPI_LIST[] = { 800, 1600, 3200, 6400, 12800 };

/* ------------------------------------------------------------------ */
/* Driver private state                                                */
/* ------------------------------------------------------------------ */

struct redragon_data {
	uint8_t active_profile;
};

/* ------------------------------------------------------------------ */
/* HID interface matching                                              */
/* ------------------------------------------------------------------ */

/*
 * The config lives on a vendor usage page (0xffa0). Accept the hidraw node
 * that exposes the vendor page (this is the config collection, distinct from
 * the boot mouse collection).
 */
static int
redragon_test_hidraw(struct ratbag_device *device)
{
	return ratbag_hidraw_has_vendor_page(device) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Low-level feature-report helpers                                    */
/* ------------------------------------------------------------------ */

/* Send a command feature report (type 0x02). `buf` already holds family/opcode. */
static int
redragon_send_cmd(struct ratbag_device *device, uint8_t *buf, size_t len)
{
	int rc;

	buf[0] = REDRAGON_TYPE_CMD;
	rc = ratbag_hidraw_set_feature_report(device, REDRAGON_TYPE_CMD, buf, len);
	if (rc < 0) {
		log_error(device->ratbag,
			  "Unable to send a feature report: %d\n", rc);
		return rc;
	}

	msleep(REDRAGON_WRITE_CHUNK_DELAY_MS);
	return 0;
}

/*
 * Query a value: send a request (family 0xf2, 16 bytes), wait, read the
 * response (16 bytes).
 * TODO(hardware-validate): response echo + payload layout.
 */
static int
redragon_query(struct ratbag_device *device, uint8_t opcode, uint8_t arg,
	       uint8_t arg2, uint8_t *resp, size_t resplen)
{
	uint8_t req[REDRAGON_QUERY_SIZE] = {0};
	int rc;

	req[0] = REDRAGON_TYPE_CMD;
	req[1] = REDRAGON_FAMILY_QUERY;
	req[2] = opcode;
	req[3] = arg;
	req[4] = arg2;

	rc = ratbag_hidraw_set_feature_report(device, REDRAGON_TYPE_CMD, req,
					      sizeof(req));
	if (rc < 0)
		return rc;

	msleep(REDRAGON_QUERY_DELAY_MS);

	rc = ratbag_hidraw_get_feature_report(device, REDRAGON_TYPE_RESP, resp,
					      resplen);
	return rc < 0 ? rc : 0;
}

/* ------------------------------------------------------------------ */
/* Encoding helpers                                                    */
/* ------------------------------------------------------------------ */

static uint8_t
redragon_encode_report_rate(unsigned int rate)
{
	for (size_t i = 0; i < ARRAY_LENGTH(REDRAGON_REPORT_RATES); i++)
		if (REDRAGON_REPORT_RATES[i] == rate)
			return (uint8_t)i;
	return 0;
}

static uint8_t
redragon_encode_dpi(unsigned int dpi)
{
	for (size_t i = 0; i < ARRAY_LENGTH(REDRAGON_DPI_LIST); i++)
		if (REDRAGON_DPI_LIST[i] == dpi)
			return (uint8_t)i;
	return 0;
}

/* Device button action codes (the "Fun" value in a button record). */
#define REDRAGON_ACT_LEFT	1
#define REDRAGON_ACT_RIGHT	2
#define REDRAGON_ACT_MIDDLE	3
#define REDRAGON_ACT_PREV	4
#define REDRAGON_ACT_NEXT	5
#define REDRAGON_ACT_MACRO	6
#define REDRAGON_ACT_DPI_UP	12
#define REDRAGON_ACT_DPI_DOWN	48
#define REDRAGON_ACT_DBLCLICK	49

/* Map a ratbag button action to the device's action code. */
static uint8_t
redragon_action_code(const struct ratbag_button_action *action)
{
	switch (action->type) {
	case RATBAG_BUTTON_ACTION_TYPE_BUTTON:
		/* mouse buttons 1..5 == codes 1..5 */
		return (uint8_t)action->action.button;
	case RATBAG_BUTTON_ACTION_TYPE_SPECIAL:
		switch (action->action.special) {
		case RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_UP:
			return REDRAGON_ACT_DPI_UP;
		case RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_DOWN:
			return REDRAGON_ACT_DPI_DOWN;
		case RATBAG_BUTTON_ACTION_SPECIAL_DOUBLECLICK:
			return REDRAGON_ACT_DBLCLICK;
		default:
			return 0;
		}
	case RATBAG_BUTTON_ACTION_TYPE_MACRO:
		return REDRAGON_ACT_MACRO;
	default:
		return 0;
	}
}

/* ------------------------------------------------------------------ */
/* Feature setters                                                     */
/* ------------------------------------------------------------------ */

static int
redragon_set_report_rate(struct ratbag_device *device, unsigned int rate)
{
	uint8_t buf[REDRAGON_QUERY_SIZE] = {0};

	buf[1] = REDRAGON_FAMILY_SET;
	buf[2] = REDRAGON_OP_SET_POLL_RATE;
	buf[3] = redragon_encode_report_rate(rate);	/* TODO(hardware-validate) */

	return redragon_send_cmd(device, buf, sizeof(buf));
}

static int
redragon_set_dpi(struct ratbag_device *device,
		 struct ratbag_resolution *resolution)
{
	uint8_t buf[REDRAGON_QUERY_SIZE] = {0};

	/*
	 * TODO(hardware-validate): the DPI write opcode/payload. The vendor
	 * tool exposes QueryDpi and "Send dpi led Refesh". Packed as stage
	 * index + raw code for now.
	 */
	buf[1] = REDRAGON_FAMILY_SET;
	buf[2] = REDRAGON_OP_QUERY_DPI;
	buf[3] = (uint8_t)resolution->index;
	buf[4] = redragon_encode_dpi(resolution->dpi_x);

	return redragon_send_cmd(device, buf, sizeof(buf));
}

static int
redragon_set_led(struct ratbag_device *device, struct ratbag_led *led)
{
	uint8_t buf[REDRAGON_REPORT_SIZE] = {0};

	/* Recovered LED write: type 0x03, family 0xf3, opcode 0x46. */
	buf[0] = REDRAGON_TYPE_RESP;
	buf[1] = REDRAGON_FAMILY_BUTTON;
	buf[2] = REDRAGON_OP_LED_WRITE;
	buf[3] = 0x04;
	buf[4] = 0x32;
	buf[5] = led->color.red;
	buf[6] = led->color.green;
	buf[7] = led->color.blue;
	/*
	 * Brightness is encoded as `9 - raw` in the vendor tool.
	 * TODO(hardware-validate): mode / brightness / breath-duration bytes
	 * and the per-zone record layout.
	 */
	buf[8] = (uint8_t)(9 - (led->brightness * 8) / 255);

	return redragon_send_cmd(device, buf, REDRAGON_QUERY_SIZE);
}

static int
redragon_set_button(struct ratbag_device *device, struct ratbag_button *button)
{
	uint8_t buf[REDRAGON_REPORT_SIZE] = {0};
	uint8_t code = redragon_action_code(&button->action);

	/*
	 * Recovered button refresh: family 0xf3, opcode 0x48, header
	 * `02 F3 48 04`, per-button record at buf[11..] (0x80 marker).
	 *
	 * TODO(hardware-validate): the exact record packing. buf[11]=0x80 and
	 * the multi-record layout are recovered; the slot/action/macro field
	 * offsets below are a best-effort reconstruction. Confirm against a
	 * QuerySingleButton dump (the probe logs raw query bytes) and then
	 * finalise here.
	 */
	buf[1] = REDRAGON_FAMILY_BUTTON;
	buf[2] = REDRAGON_OP_BUTTON_REFRESH;
	buf[3] = 0x04;
	buf[4] = 0x08;

	buf[11] = 0x80;			/* record marker (recovered) */
	buf[12] = (uint8_t)button->index;	/* button slot */
	buf[13] = code;			/* device action code */

	/* Macro KeyInfo (map/L/H) lives in the following bytes for macros. */
	if (button->action.type == RATBAG_BUTTON_ACTION_TYPE_MACRO &&
	    button->action.macro) {
		/* TODO(hardware-validate): encode macro events into the record. */
	}

	return redragon_send_cmd(device, buf, REDRAGON_QUERY_SIZE);
}

static int
redragon_set_angle_snapping(struct ratbag_device *device,
			    struct ratbag_profile *profile)
{
	uint8_t buf[REDRAGON_QUERY_SIZE] = {0};

	/* TODO(hardware-validate): angle-snapping opcode. */
	buf[1] = REDRAGON_FAMILY_SET;
	buf[2] = 0x00;
	buf[3] = profile->angle_snapping > 0 ? 1 : 0;

	return redragon_send_cmd(device, buf, sizeof(buf));
}

static int
redragon_set_active_profile(struct ratbag_device *device, unsigned int index)
{
	struct redragon_data *drv_data = ratbag_get_drv_data(device);
	uint8_t buf[REDRAGON_QUERY_SIZE] = {0};

	/* TODO(hardware-validate): profile-select opcode. */
	buf[1] = REDRAGON_FAMILY_SET;
	buf[2] = 0x01;
	buf[3] = (uint8_t)index;

	drv_data->active_profile = (uint8_t)index;
	return redragon_send_cmd(device, buf, sizeof(buf));
}

/* ------------------------------------------------------------------ */
/* Commit / probe / remove                                             */
/* ------------------------------------------------------------------ */

static int
redragon_commit_profile(struct ratbag_device *device,
			struct ratbag_profile *profile)
{
	struct ratbag_resolution *resolution;
	struct ratbag_button *button;
	struct ratbag_led *led;
	int rc;

	rc = redragon_set_report_rate(device, profile->hz);
	if (rc)
		return rc;

	if (profile->angle_snapping_dirty) {
		rc = redragon_set_angle_snapping(device, profile);
		if (rc)
			return rc;
	}

	ratbag_profile_for_each_resolution(profile, resolution) {
		if (!resolution->dirty)
			continue;
		rc = redragon_set_dpi(device, resolution);
		if (rc)
			return rc;
	}

	ratbag_profile_for_each_button(profile, button) {
		if (!button->dirty)
			continue;
		rc = redragon_set_button(device, button);
		if (rc)
			return rc;
	}

	ratbag_profile_for_each_led(profile, led) {
		if (!led->dirty)
			continue;
		rc = redragon_set_led(device, led);
		if (rc)
			return rc;
	}

	return 0;
}

static int
redragon_commit(struct ratbag_device *device)
{
	struct ratbag_profile *profile;

	list_for_each(profile, &device->profiles, link) {
		if (!profile->dirty)
			continue;
		int rc = redragon_commit_profile(device, profile);
		if (rc)
			return rc;
	}

	return 0;
}

static int
redragon_probe(struct ratbag_device *device)
{
	struct redragon_data *drv_data;
	struct ratbag_profile *profile;
	struct ratbag_resolution *resolution;
	struct ratbag_button *button;
	struct ratbag_led *led;

	if (ratbag_find_hidraw(device, redragon_test_hidraw))
		return -ENODEV;

	drv_data = zalloc(sizeof(*drv_data));
	if (!drv_data)
		return -ENOMEM;
	ratbag_set_drv_data(device, drv_data);

	/*
	 * Best-effort read-back: query the poll rate and log the raw response
	 * so the wire layout can be calibrated against real hardware. Full
	 * config read-back (QueryDpi / QueryLedState / QuerySingleButton)
	 * still needs its response offsets confirmed; until then we seed the
	 * ratbag objects from the vendor defaults below and expose the profile
	 * as write-capable.
	 */
	{
		uint8_t resp[REDRAGON_QUERY_SIZE] = {0};
		if (redragon_query(device, REDRAGON_OP_QUERY_POLL_RATE, 0, 0,
				   resp, sizeof(resp)) == 0) {
			char hex[REDRAGON_QUERY_SIZE * 3 + 1] = {0};
			for (size_t i = 0; i < REDRAGON_QUERY_SIZE; i++)
				snprintf(hex + i * 3, 4, "%02x ", resp[i]);
			log_info(device->ratbag,
				 "X-41 Pro poll-rate query response: %s\n", hex);
		}
	}

	/*
	 * TODO(hardware-validate): read the current onboard configuration via
	 * the family 0xf2 query commands and populate the ratbag objects.
	 */
	ratbag_device_init_profiles(device,
				   REDRAGON_NUM_PROFILES,
				   REDRAGON_NUM_RESOLUTIONS,
				   REDRAGON_NUM_BUTTONS,
				   REDRAGON_NUM_LEDS);

	ratbag_device_for_each_profile(device, profile) {
		profile->is_active = (profile->index == drv_data->active_profile);
		profile->hz = REDRAGON_REPORT_RATES[ARRAY_LENGTH(REDRAGON_REPORT_RATES) - 1];
		profile->angle_snapping = 0;

		ratbag_profile_set_cap(profile, RATBAG_PROFILE_CAP_WRITE_ONLY);
		ratbag_profile_set_report_rate_list(profile,
						    REDRAGON_REPORT_RATES,
						    ARRAY_LENGTH(REDRAGON_REPORT_RATES));

		ratbag_profile_for_each_resolution(profile, resolution) {
			size_t idx = resolution->index < ARRAY_LENGTH(REDRAGON_DPI_LIST)
				     ? resolution->index
				     : ARRAY_LENGTH(REDRAGON_DPI_LIST) - 1;

			ratbag_resolution_set_dpi_list(resolution, REDRAGON_DPI_LIST,
						       ARRAY_LENGTH(REDRAGON_DPI_LIST));
			ratbag_resolution_set_cap(resolution,
						  RATBAG_RESOLUTION_CAP_SEPARATE_XY_RESOLUTION);
			resolution->dpi_x = REDRAGON_DPI_LIST[idx];
			resolution->dpi_y = REDRAGON_DPI_LIST[idx];
			resolution->is_active = (resolution->index == 0);
			resolution->is_default = (resolution->index == 0);
		}

		ratbag_profile_for_each_button(profile, button) {
			ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_BUTTON);
			ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_SPECIAL);
			ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_KEY);
			ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_MACRO);
			ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_NONE);

			/*
			 * Device default actions (see PROTOCOL-X41PRO.md button
			 * map). Read-back will overwrite these with the device's
			 * real config once QuerySingleButton parsing is calibrated.
			 */
			switch (button->index) {
			case 0:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_BUTTON;
				button->action.action.button = 1;
				break;
			case 1:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_BUTTON;
				button->action.action.button = 2;
				break;
			case 2:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_BUTTON;
				button->action.action.button = 3;
				break;
			case 3:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_BUTTON;
				button->action.action.button = 4;
				break;
			case 4:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_BUTTON;
				button->action.action.button = 5;
				break;
			case 5:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_SPECIAL;
				button->action.action.special = RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_UP;
				break;
			case 6:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_SPECIAL;
				button->action.action.special = RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_DOWN;
				break;
			case 7:
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_SPECIAL;
				button->action.action.special = RATBAG_BUTTON_ACTION_SPECIAL_DOUBLECLICK;
				break;
			default:
				/* macro1/2/3: real macro populated on read-back. */
				button->action.type = RATBAG_BUTTON_ACTION_TYPE_BUTTON;
				button->action.action.button = 1;
				break;
			}
		}

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
