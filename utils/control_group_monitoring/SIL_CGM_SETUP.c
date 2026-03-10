/* SIL_CGM_SETUP.c
 *
 * Operation: Setup control group subtree and directory. Does so by first
 * getting the user's cgroup slice and building a path beneath it.
 * Type: Setup - sets up paths and cgroups for data operations by other
 * binaries.
 *
 * See CGM.h for more information.
 *
 * Last Updated: 03/10/2026
 * Author: Noel Rodriguez
 */

#include "CGM.h"
#define BASE "/sys/fs/cgroup/"

int
sil_cgm_setup (const char *cgroup, int writes, char **tgids) {
	char slice[256];
	char cg_path[512];

	size_t len;	
	int tw; // Truncation Watcher.
	int fd;

	if (!cgroup || *cgroup == '\0' || !tgids) {
		fprintf(stderr, "SIL_CGM_SETUP: bad args\n");
		return ARG_FAULT;
	}

	if (sil_r_cgroup_slice(slice, sizeof(slice))) {
		fprintf(stderr, "SIL_CGM_SETUP: sil_r_cgroup_slice\n");
		return FAULT;
		}
	
	tw = snprintf(cg_path, sizeof(cg_path), 
			"%s%s/sil/%s", BASE, slice, cgroup);
	if (tw < 0 || tw >= (int)sizeof(cg_path)) {
		fprintf(stderr, "SIL_CGM_SETUP: string");
		return ARG_FAULT;
	}	

	if (sil_mkdir_p(cg_path)) {
		perror("SIL_CGM_SETUP: mkdir -p");
		return SYS_FAULT;
	}	

	len = strlen(cg_path);
	tw = snprintf(cg_path + len, sizeof(cg_path) - len, 
			"/cgroup.procs"); 

	if (tw < 0 || tw >= (int)(sizeof(cg_path) - len)) {
		fprintf(stderr, "SIL_CGM_SETUP: string");
		return ARG_FAULT;
	}

	fd = open(cg_path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("SIL_CGM_SETUP: open");
		return SYS_FAULT;
	}
	
	len = 0; // Best effort. 
	for (; writes >= 0; writes--) {
		char line[64];
		if (!*(tgids + writes) || (**(tgids + writes) == '\0')) {
			fprintf(stderr, "SIL_CGM_SETUP: bad tgid\n");
			len = 1;
			continue;
		}
		
		tw = snprintf(line, sizeof(line), "%s\n", 
				*(tgids + writes));
		
		if (tw < 0 || tw >= (int)sizeof(line)) {
			fprintf(stderr, "SIL_CGM_SETUP: string\n");
			len = 1;
			continue;
		}

		if (write(fd, line, (size_t)tw) != tw) {
			perror("SIL_CGM_SETUP: write");
			len = 1;
			continue;
		}
	}

	close(fd);
	return len ? SYS_FAULT : OK;
}

int 
main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <cgroup> <TGID> <TGID2> ...\n", *argv);
		return ARG_FAULT;
	}

	return sil_cgm_setup(*(argv + 1), argc - 3, argv + 2);

}
