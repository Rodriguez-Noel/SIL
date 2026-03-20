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
#define BASE "/sys/fs/cgroup"

int
sil_cgm_setup(const char *cgroup, int writes, char **tgids) {
	char slice[256];
	char cg_path[512];

	size_t len;
	int tw;
	int fd;

	int moved;
	int skipped_esrch;
	int skipped_perm;
	int skipped_bad;
	int hard_fail;

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
		fprintf(stderr, "SIL_CGM_SETUP: string\n");
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
		fprintf(stderr, "SIL_CGM_SETUP: string\n");
		return ARG_FAULT;
	}

	fd = open(cg_path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("SIL_CGM_SETUP: open");
		return SYS_FAULT;
	}

	moved = 0;
	skipped_esrch = 0;
	skipped_perm = 0;
	skipped_bad = 0;
	hard_fail = 0;

	for (; writes >= 0; writes--) {
		char line[64];
		ssize_t wr;

		if (!*(tgids + writes) || (**(tgids + writes) == '\0')) {
			fprintf(stderr, "SIL_CGM_SETUP: bad tgid\n");
			skipped_bad++;
			continue;
		}

		tw = snprintf(line, sizeof(line), "%s\n", 
				*(tgids + writes));
		
		if (tw < 0 || tw >= (int)sizeof(line)) {
			fprintf(stderr, "SIL_CGM_SETUP: string\n");
			skipped_bad++;
			continue;
		}

		wr = write(fd, line, (size_t)tw);
		if (wr == tw) {
			moved++;
			continue;
		}

		if (wr < 0) {
			if (errno == ESRCH) {
				skipped_esrch++;
				continue;
			}
			if (errno == EPERM || errno == EACCES) {
				skipped_perm++;
				continue;
			}
			perror("SIL_CGM_SETUP: write");
			hard_fail++;
			continue;
		}

		fprintf(stderr, "SIL_CGM_SETUP: short write\n");
		hard_fail++;
	}

	close(fd);

	fprintf(stderr, "SIL_CGM_SETUP: moved=%d"
			" skipped_esrch=%d skipped_perm=%d"
			" skipped_bad=%d hard_fail=%d\n",  
			moved, skipped_esrch, skipped_perm, 
			skipped_bad, hard_fail); 

	if (moved > 0)
		return OK;

	return SYS_FAULT;
}

int
main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <cgroup> <TGID> <TGID2> ...\n", *argv);
		return ARG_FAULT;
	} 

	return sil_cgm_setup(*(argv + 1), argc - 3, argv + 2);
}
