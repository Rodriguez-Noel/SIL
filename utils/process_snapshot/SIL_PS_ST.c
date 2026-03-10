/* SIL_PS_ST.c
 *
 * Operation: Read tsv from STDIN then setup and write snapshot file.
 * Type: Atomic
 *
 * See PS.h for additional information.
 *
 * Last Updated 03/07/2026
 * Author: Noel Rodriguez
 */

#include "PS.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

int sil_mkdir_p (const char *path);
int sil_pwd (const char *path, char *pwdbuf, size_t bufsz);
int sil_write_snapshot (const char *path);

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
sil_pwd (const char *path, char *pwdbuf, size_t bufsz) {
	size_t i, len;
	
	if (!path || !pwdbuf || bufsz == 0)
		return ARG_FAULT;

	len = strlen(path);
	if (len == 0 || len >= bufsz)
		return ARG_FAULT;

	snprintf(pwdbuf, bufsz, "%s", path);

	for (i = len - 1; i > 0; i--) {
		if (*(pwdbuf + i) == '/') {
			*(pwdbuf + i) = '\0';
			return OK;
		}
	}

	snprintf(pwdbuf, bufsz, ".");
	return OK;
}

int
sil_write_snapshot (const char *path) {
	int fd;
	FILE *fs;
	char line[256];
	char pwd[512];

	if (!path || *path == '\0') {
		fprintf(stderr, "SIL_PS_ST: path\n");
		return ARG_FAULT;
	}
	
	if (sil_pwd(path, pwd, sizeof(pwd))) {
		fprintf(stderr, "SIL_PS_ST: pwd\n"); 
		return FAULT;
	}

	if (sil_mkdir_p(pwd)) {
		perror("SIL_PS_ST: mkdir -p");
		return SYS_FAULT; 
	}	

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		perror("SIL_PS_ST: open");
		return SYS_FAULT;
	}

	if (flock(fd, LOCK_EX)) {
		perror("SIL_PS_ST: flock");
		close(fd);
		return SYS_FAULT;
	}
	
	if (ftruncate(fd, 0)) {
		perror("SIL_PS_ST: ftruncate");
		close(fd);
		return SYS_FAULT;
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		perror("SIL_PS_ST: lseek");
		close(fd);
		return SYS_FAULT;
	}
	
	fs = fdopen(fd, "w");
	if (!fs) {
		perror("SIL_PS_ST: fdopen");
		close(fd);
		return SYS_FAULT;
	}

	fprintf(fs, "PID\tTGID\tUID\tTHREADS\tCOMM\n");

	while (fgets(line, sizeof(line), stdin))
		fputs(line, fs);

	fflush(fs);
	fclose(fs);
	return OK;
}

int
main (int argc, char** argv) {
	const char *path;

	if (!(argc == 2)) {
		fprintf(stderr, "Usage: %s <path>\n", *argv);
		return ARG_FAULT;
	}

	path = *(argv + 1);
	if (!path || *path == '\0') {
		fprintf(stderr, "Usage: %s <path>\n", *argv);
		return ARG_FAULT;
	}
	
	return sil_write_snapshot(path);
}
