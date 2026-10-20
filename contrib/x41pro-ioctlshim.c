/*
 * LD_PRELOAD ioctl shim: log HID feature-report traffic.
 *
 * Intercepts libc ioctl() and logs every 'H' (hidraw) request + response
 * buffer to $IOCTL_LOG (default /tmp/opencode/x41-ioctl.log). Load this into
 * RDCfg.exe running under Wine to capture the exact feature reports the vendor
 * tool exchanges with the mouse (query framing, report IDs, button records).
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o /tmp/x41shim.so contrib/x41pro-ioctlshim.c -ldl
 *
 * Use (see contrib/x41pro-capture.sh):
 *   LD_PRELOAD=/tmp/x41shim.so IOCTL_LOG=/tmp/opencode/x41-ioctl.log wine RDCfg.exe
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

static int (*real_ioctl)(int, unsigned long, ...);
static FILE *lg;

static void init(void)
{
	if (!real_ioctl)
		real_ioctl = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
	if (!lg) {
		const char *p = getenv("IOCTL_LOG");
		lg = fopen(p ? p : "/tmp/opencode/x41-ioctl.log", "a");
		if (lg)
			setvbuf(lg, NULL, _IOLBF, 0);
	}
}

static void dump(const char *tag, int fd, unsigned long req, unsigned char *buf, unsigned size, int ret)
{
	if (!lg)
		return;
	unsigned type = (req >> 8) & 0xff;
	if (type != 'H')
		return;
	fprintf(lg, "%s fd=%d cmd=0x%08lx size=%u ret=%d :", tag, fd, req, size, ret);
	unsigned n = size < 320 ? size : 320;
	if (buf) {
		for (unsigned i = 0; i < n; i++)
			fprintf(lg, " %02x", buf[i]);
	}
	fprintf(lg, "\n");
}

int ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	void *arg;
	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);

	init();

	unsigned size = (req >> 16) & 0x3fff;
	unsigned char *buf = (unsigned char *)arg;

	/* log the outgoing buffer (the request for SET) */
	dump("IOCTL", fd, req, buf, size, -999);

	int r = real_ioctl(fd, req, arg);

	/* log the returned buffer (the response for GET) */
	dump("  -> ", fd, req, buf, size, r);
	return r;
}
