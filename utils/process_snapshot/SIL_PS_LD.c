/* SIL_PS_LD.c 
 * 
 * Operation: Load process snapshot to STDOUT for consumption by store op.
 * Type: Atomic - this binary should not be interrupted unless it fails.
 *
 * See PS.h for additional information.
 * 
 * Last Updated: 03/07/2026
 * Author: Noel Rodriguez
 */

#include "PS.h"

#include <dirent.h>
#include <ctype.h>

int sil_is_pid_dir (const char* s);
int sil_r_status_fields (int pid, int *tgid, int *uid, int *threads);
void sil_r_comm (int pid, char comm[16]);

int // Boolean Function: STANDARD EXIT CODES DO NOT APPLY.
sil_is_pid_dir (const char *s) {
	for (; *s; s++) {
		if (!isdigit((unsigned char) *s)) 
			return 0;
	}
	return 1;
}

int 
sil_r_status_fields (int pid, int *tgid, int *uid, int *threads) {
	char path[64];
	char line[256];
	FILE *f;

	if (!tgid || !uid || !threads) 
		return ARG_FAULT;

	*tgid = -1;
	*uid = -1;
	*threads = -1;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);

	f = fopen(path, "r");

	if (!f)
		return SYS_FAULT;

	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Tgid:", 5)) 
			sscanf(line, "Tgid:\t%d", tgid);	
		else if (!strncmp(line, "Uid:", 4)) 
			sscanf(line, "Uid:\t%d", uid);
		else if (!strncmp(line, "Threads:", 8))
			sscanf(line, "Threads:\t%d", threads);

		if (*tgid != -1 && *uid != -1 && *threads != -1)
			break;
	}
	
	fclose(f);

	if (*tgid == -1 || *uid == -1)
		return FAULT;
	
	return OK;
}

void 
sil_r_comm (int pid, char comm[16]) {
	char path[64];
	FILE *f;
	int i;

	if (!comm)
		return;

	memset(comm, 0, 16);
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");

	if (!f)
		return;

	for (i = 0; i < 15; i++) {
		int c = fgetc(f);
		if (c == EOF || c == '\n')
			break;
	
		comm[i] = (char)c;
	}

	fclose(f);
}

int
main(void) {
	DIR *d;
	struct dirent *e;

	d = opendir("/proc");
	
	if (!d) {
		perror("opendir(/proc)");
		return SYS_FAULT;
	}

	while ((e = readdir(d))) {
		int pid;
		int tgid;
		int uid;
		int thr;
		char comm[16];

		if (!sil_is_pid_dir(e->d_name))
			continue;

		pid = atoi(e->d_name);

		if (sil_r_status_fields(pid, &tgid, &uid, &thr))
			continue;

		if (!(pid == tgid))
			continue;

		sil_r_comm(pid, comm);

		printf("%d\t%d\t%d\t%d\t%s\n", pid, tgid, uid, thr, comm);
	}

	closedir(d);
	return OK;
}
