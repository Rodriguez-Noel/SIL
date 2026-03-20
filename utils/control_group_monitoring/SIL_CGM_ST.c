/* SIL_CGM_ST.c
 *
 * Operation: Store CGM TSV data from STDIN to a target file.
 * Type: Atomic - this binary should not be interrupted unless it fails.
 *
 * See CGM.h for additional information.
 */

#include "CGM.h"

int sil_cgm_st(char *path);

int
sil_cgm_st(char *path) { 
	char buf[4096]; 
	ssize_t got, off, wrote; 
	int fd; 
	
	if (!path || *path == '\0') 
		return ARG_FAULT; 

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644); 
	if (fd < 0) { 
		fprintf(stderr, "SIL_CGM_ST: open\n"); 
		return SYS_FAULT;
	} 
	
	for (;;) { 

		got = read(STDIN_FILENO, buf, sizeof(buf)); 
		if (got < 0) { 
			fprintf(stderr, "SIL_CGM_ST: read\n"); 
			close(fd); 
			return SYS_FAULT; 
		} 
		
		if (got == 0) 
			break; 

		off = 0;
		while (off < got) {
			wrote = write(fd, buf + off, (size_t)(got - off));
			if (wrote < 0) { 
				fprintf(stderr, "SIL_CGM_ST: write\n");
				close(fd); 
				return SYS_FAULT; 
			} 

			off += wrote;
		} 
	}
	
	close(fd); 
	return OK; 
}

int
main(int argc, char **argv) {
	
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <path>\n", argv[0]); 
		return ARG_FAULT; 
	} 
	if (!argv[1] || *argv[1] == '\0') { 
		fprintf(stderr, "Usage: %s <path>\n", argv[0]);
		return ARG_FAULT; 
	} 

	return sil_cgm_st(argv[1]);
} 
