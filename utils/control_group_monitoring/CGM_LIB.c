/* CGM_LIB.c
 *
 * Local library for common functions.
 * Used by: SIL_CGM_SETUP.c, SIL_CGM_ATTACH_BPF.c, SIL_CGM_DUMP_ST.c
 */

#include "CGM.h"

int
sil_mkdir_p (const char *path) {
	char tmp[512];
	size_t n;

	if (!path || *path == '\0')
		return ARG_FAULT;

	snprintf(tmp, sizeof(tmp), "%s", path);

	for (n = 1; *(tmp + n); n++) {
		if (*(tmp + n) == '/') {
			*(tmp + n) = '\0';

			if ((mkdir(tmp, 0755) != 0 && errno != EEXIST))
				return SYS_FAULT;

			*(tmp + n) = '/';
		}
	}

	if ((mkdir(tmp, 0755) != 0 && errno != EEXIST))
		return SYS_FAULT;

	return OK;
}

int 
sil_r_cgroup_slice (char *buf, size_t bufsz) {
	FILE *f;
	char line[512];
	char *capture; // Exploring pointer naming conventions. Alt: walker?
	
	if (!buf || bufsz == 0) 
		return ARG_FAULT;
	
	*buf = '\0';

	f = fopen("/proc/self/cgroup", "r");
	if (!f) {
		perror("CGM_LIB: open");
		return SYS_FAULT;
	}

	while (fgets(line, sizeof(line), f)) {
		size_t len;
		capture = strstr(line, "::");

		if (!p)
			continue;

		capture += 2;
		len = strcspn(p, "\r\n");
		*(capture + len) = '\0';
		
		if (!(*capture == '/'))
			continue;
		
		if (strlen(capture) >= bufsz) {
			fclose(f);
			return FAULT;
		}	

		snprintf(buf, bufsz, "%s", capture);
		fclose(f);
		return 0;
	}
	fclose(f);
	return FAULT;
}
