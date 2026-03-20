/* CGM_LIB.c
 *
 * Local library for common functions.
 * Used by: SIL_CGM_SETUP.c, SIL_CGM_ATTACH_BPF.c, SIL_CGM_DUMP_ST.c
 */

#include "CGM.h"

int 
sil_mkdir_p(const char *path) { 
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

void 
sil_strip_nested_sil_suffix(char *path) { 
	char *mark; 
	if (!path || *path == '\0') 
		return; 
	/*
	 * Normalize:
	 *   /user.slice/.../scope/sil/foo/sil/bar
	 * to:
	 *   /user.slice/.../scope
	 * This POS bug has been TEMPORARILY fixed at 3:30AM. 
	 */ 
	mark = strstr(path, "/sil/"); 
	if (mark) 
		*mark = '\0'; 
} 
int 
sil_r_cgroup_slice(char *buf, size_t bufsz) { 
	FILE *f; 
	char line[1024]; 
	char normalized[1024]; 
	char *capture; 
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
		if (!capture) 
			continue; 
		capture += 2; 
		len = strcspn(capture, "\r\n"); 
		*(capture + len) = '\0'; 
		if (!(*capture == '/')) 
			continue; 
		snprintf(normalized, sizeof(normalized), "%s", capture); 
		sil_strip_nested_sil_suffix(normalized); 
		if (strlen(normalized) >= bufsz) { 
			fclose(f); 
			return FAULT; 
		} 
		snprintf(buf, bufsz, "%s", normalized); 
		fclose(f); 
		return OK; 
	} 

	fclose(f); 
	return FAULT;
}
