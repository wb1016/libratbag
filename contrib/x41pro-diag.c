/*
 * X-41 Pro diagnostic (C): report descriptor + query sweep.
 *
 * Uses <linux/hidraw.h> so the ioctl numbers match the running kernel
 * (the Python version computed them by hand and got EINVAL on HIDIOCGRDESC).
 *
 * Phase 1: read each node's report descriptor -> report IDs + usage pages
 *          (identifies the config interface, vendor page 0xffa0).
 * Phase 2: query sweep with the discovered report IDs; print non-zero replies.
 *
 * Build:  gcc -O2 -o /tmp/x41-diag contrib/x41pro-diag.c
 * Run:    sudo /tmp/x41-diag
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <linux/hidraw.h>
#include <errno.h>

static int usb_match(const char *hidraw)
{
	char sys[256], real[4096];
	snprintf(sys, sizeof(sys), "/sys/class/hidraw/%s/device", hidraw);
	if (!realpath(sys, real))
		return 0;
	char *p = strdup(real);
	for (int i = 0; i < 12; i++) {
		char iv[4200], ip[4200], v[16] = {0}, pr[16] = {0};
		snprintf(iv, sizeof(iv), "%s/idVendor", p);
		snprintf(ip, sizeof(ip), "%s/idProduct", p);
		FILE *f = fopen(iv, "r");
		if (f) {
			if (fscanf(f, "%15s", v) != 1) v[0] = 0;
			fclose(f);
			FILE *g = fopen(ip, "r");
			if (g) {
				if (fscanf(g, "%15s", pr) != 1) pr[0] = 0;
				fclose(g);
			}
			int ok = (!strcmp(v, "36b7") && !strcmp(pr, "fd15"));
			free(p);
			return ok;
		}
		char *slash = strrchr(p, '/');
		if (!slash || slash == p) break;
		*slash = 0;
	}
	free(p);
	return 0;
}

static void parse_desc(const unsigned char *d, int n, int *repids, int *nrep)
{
	*nrep = 0;
	printf("   report IDs : ");
	for (int i = 0; i < n; ) {
		unsigned char b = d[i];
		if (b == 0xFE) { i += 3 + d[i + 1]; continue; }
		int sz = (int[]){0, 1, 2, 4}[b & 3];
		int typ = (b >> 2) & 3, tag = (b >> 4) & 0xF;
		unsigned val = 0;
		for (int k = 0; k < sz; k++) val |= (unsigned)d[i + 1 + k] << (8 * k);
		if (typ == 1 && tag == 8) { printf("0x%02x ", val); repids[(*nrep)++] = val; }
		i += 1 + sz;
	}
	if (!*nrep) printf("(none = unnumbered)");
	printf("\n   usage pages: ");
	for (int i = 0; i < n; ) {
		unsigned char b = d[i];
		if (b == 0xFE) { i += 3 + d[i + 1]; continue; }
		int sz = (int[]){0, 1, 2, 4}[b & 3];
		int typ = (b >> 2) & 3, tag = (b >> 4) & 0xF;
		unsigned val = 0;
		for (int k = 0; k < sz; k++) val |= (unsigned)d[i + 1 + k] << (8 * k);
		if (typ == 1 && tag == 0) printf("0x%04x%s ", val, val >= 0xFF00 ? "(VENDOR)" : "");
		i += 1 + sz;
	}
	printf("\n");
}

static int do_query(int fd, int sid, int rid, int addr)
{
	unsigned char req[16] = {0};
	req[0] = (unsigned char)sid;
	req[1] = 0xf2;
	req[2] = addr & 0xFF;
	req[3] = (addr >> 8) & 0xFF;
	req[4] = 0x04;
	int r = ioctl(fd, HIDIOCSFEATURE(16), req);
	if (r < 0) return -1;
	usleep(8000);
	unsigned char resp[64] = {0};
	resp[0] = (unsigned char)rid;
	r = ioctl(fd, HIDIOCGFEATURE(sizeof(resp)), resp);
	if (r < 0) return -1;
	int nonzero = 0;
	for (int i = 1; i < (int)sizeof(resp); i++) if (resp[i]) nonzero = 1;
	if (nonzero) {
		printf("    SEND=0x%02x RESP=0x%02x addr 0x%03x: ", sid, rid, addr);
		for (int i = 0; i < 24; i++) printf("%02x", resp[i]);
		printf("\n");
	}
	return nonzero;
}

int main(void)
{
	if (geteuid() != 0) { printf("run as root\n"); return 1; }

	DIR *dir = opendir("/sys/class/hidraw");
	if (!dir) { perror("opendir"); return 1; }

	struct { int fd; int repids[32]; int nrep; int vend; } nodes[16];
	int nn = 0;
	struct dirent *de;

	printf("=== Phase 1: report descriptors ===\n");
	while ((de = readdir(dir)) && nn < 16) {
		if (strncmp(de->d_name, "hidraw", 6)) continue;
		if (!usb_match(de->d_name)) continue;
		char dev[64];
		snprintf(dev, sizeof(dev), "/dev/%s", de->d_name);
		int fd = open(dev, O_RDWR | O_NONBLOCK);
		if (fd < 0) { printf("  %s: open fail %s\n", de->d_name, strerror(errno)); continue; }

		struct hidraw_report_descriptor rpt;
		memset(&rpt, 0, sizeof(rpt));
		rpt.size = HID_MAX_DESCRIPTOR_SIZE;
		int r = ioctl(fd, HIDIOCGRDESC, &rpt);
		printf("  %s: HIDIOCGRDESC ret=%d (%s)\n", de->d_name, r, r < 0 ? strerror(errno) : "ok");
		nodes[nn].fd = fd;
		nodes[nn].vend = 0;
		nodes[nn].nrep = 0;
		if (r >= 0) {
			parse_desc(rpt.value, rpt.size, nodes[nn].repids, &nodes[nn].nrep);
			for (int i = 0; i < (int)rpt.size - 1; i++) {
				if (rpt.value[i] == 0x06 && rpt.value[i + 1] == 0xA0) nodes[nn].vend = 1;
			}
			printf("     config(0xffa0)? %s\n", nodes[nn].vend ? "YES" : "no");
		}
		nn++;
	}
	closedir(dir);

	printf("\n=== Phase 2: query sweep ===\n");
	int found = 0;
	for (int k = 0; k < nn; k++) {
		int *ids = nodes[k].repids;
		int nrep = nodes[k].nrep;
		if (!nrep) { ids = (int[]){0, 1, 2, 3}; nrep = 4; }
		printf("-- node fd=%d --\n", nodes[k].fd);
		for (int a = 0; a < nrep && !found; a++)
			for (int b = 0; b < nrep && !found; b++)
				for (int addr = 0x00; addr < 0x300 && !found; addr += 4)
					if (do_query(nodes[k].fd, ids[a], ids[b], addr)) found = 1;
		if (found) break;
	}
	if (!found) printf("no non-zero data. Framing likely wrong -> capture RDCfg.exe.\n");

	for (int k = 0; k < nn; k++) close(nodes[k].fd);
	return 0;
}
