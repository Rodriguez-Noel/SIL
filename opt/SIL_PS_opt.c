/* SIL_PS_opt.c
 *
 * Operation: Setup pipe for reading and writing between LD and ST ops.
 * Type: Option/API - Abstraction for the CLI/TUI to use.
 *
 * See PS.h for additional information.
 *
 * Last Updated: 03/01/2026
 * Author: Noel Rodriguez
 */

#include "OPT.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#define LD_BIN_PATH "./staging/bin/utils/process_snapshot/SIL_PS_LD"
#define ST_BIN_PATH "./staging/bin/utils/process_snapshot/SIL_PS_ST"

int main(int argc, char **argv) {
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
/*-------------------------- End Sanitization --------------------------*/
	int pfd[2];
	pid_t ld_pid, st_pid;
	int ld_status, st_status;  
	
	if (pipe(pfd)) {
		perror("SIL_PS_opt: pipe");
		return SYS_FAULT;
	}
	
	ld_pid = fork();
	if (ld_pid < 0) {
		perror("SIL_PS_opt: fork(ld)");
		close(pfd[0]);
		close(pfd[1]);
		return SYS_FAULT;
	} 
	
	if (ld_pid == 0) {
		if (dup2(pfd[1], STDOUT_FILENO) < 0) {
			perror("SIL_PS_opt: dup2(ld)");
			_exit(EXE_FAULT);
		}

		close(pfd[0]);
		close(pfd[1]);

		execl(LD_BIN_PATH, LD_BIN_PATH, (char*) NULL);
		perror("SIL_PS_opt: execl(ld)");
		_exit(EXE_FAULT);
	}
	
	st_pid = fork();
	
	if (st_pid < 0) {
		perror("SIL_PS_opt: fork(st)");
		close(pfd[0]);
		close(pfd[1]);

		kill(ld_pid, SIGTERM);
		waitpid(ld_pid, NULL, 0);
		return SYS_FAULT;
	}
	
	if (st_pid == 0) {
		if (dup2(pfd[0], STDIN_FILENO) < 0) {
			perror("SIL_PS_opt: dup2(st)");
			_exit(EXE_FAULT);
		}
	
		close(pfd[0]);
        	close(pfd[1]);

		execl(ST_BIN_PATH, ST_BIN_PATH, path, (char *)NULL);
		perror("SIL_PS_opt: execl(ST)");
		_exit(EXE_FAULT);
	}

	close(pfd[0]);
	close(pfd[1]);

	ld_status = 0;
	st_status = 0;
	
	if (waitpid(ld_pid, &ld_status, 0) < 0) {
		perror("SIL_PS_opt: waitpid(ld)");
		return SYS_FAULT;
	}
	
	if (waitpid(st_pid, &st_status, 0) < 0) {
		perror("SIL_PS_opt: waitpid(st)");
		return SYS_FAULT;
	}
	
	if (!WIFEXITED(ld_status) || WEXITSTATUS(ld_status) != 0) {
		return SYS_FAULT;
	}
	
	if (!WIFEXITED(st_status) || WEXITSTATUS(st_status) != 0) {
		return SYS_FAULT;
	}	
	
	return OK;
}
