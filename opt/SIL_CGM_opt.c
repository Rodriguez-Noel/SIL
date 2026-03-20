/* SIL_CGM_opt.c
 *
 * Operation: Orchestrate CGM utility binaries.
 * Type: Option/API - abstraction for higher layers to use.
 *
 * Usage:
 *   SIL_CGM_opt [-l | -g] <cgroup-name> <TGID> [TGID...]
 *   SIL_CGM_opt -r [-l | -g] <cgroup-name>
 *
 * Flags:
 *   -r  refresh existing monitor only (LD -> ST)
 *   -l  lean mode
 *   -g  greedy mode
 *   no mode flag = default mode
 */

#include "OPT.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#define SETUP_BIN_PATH "./staging/bin/utils/control_group_monitoring/SIL_CGM_SETUP"
#define ATTACH_BIN_PATH "./staging/bin/utils/control_group_monitoring/SIL_CGM_ATTACH"
#define LD_BIN_PATH "./staging/bin/utils/control_group_monitoring/SIL_CGM_LD"
#define ST_BIN_PATH "./staging/bin/utils/control_group_monitoring/SIL_CGM_ST"

#define OUT_PATH "./data/cgm/cgm.tsv"

int sil_cgm_refresh(char *flag, char *cgroup_name); 
int sil_cgm_opt(char *flag, char *cgroup_name, 
		char **tgids, int tgid_count); 

int 
sil_cgm_refresh(char *flag, char *cgroup_name) { 
	int pfd[2]; 
	pid_t ld_pid, st_pid; 
	int ld_status, st_status; 
	
	if (!cgroup_name || *cgroup_name == '\0') 
		return ARG_FAULT; 
	
	if (pipe(pfd)) { 
		perror("SIL_CGM_opt: pipe(refresh)"); 
		return SYS_FAULT; 
	} 
	
	ld_pid = fork();
	if (ld_pid < 0) {
		perror("SIL_CGM_opt: fork(ld refresh)"); 
		close(pfd[0]); 
		close(pfd[1]); 
		return SYS_FAULT; 
	} 
	
	if (ld_pid == 0) { 
		if (dup2(pfd[1], STDOUT_FILENO) < 0) { 
			perror("SIL_CGM_opt: dup2(ld refresh)"); 
			_exit(EXE_FAULT); 
		} 
		close(pfd[0]); 
		close(pfd[1]); 

		if (!flag) 
			execl(LD_BIN_PATH, LD_BIN_PATH, cgroup_name, 
					(char *) NULL);
		else 
			execl(LD_BIN_PATH, LD_BIN_PATH, flag, 
					cgroup_name, (char *) NULL);
		
		perror("SIL_CGM_opt: execl(ld refresh)"); 
		_exit(EXE_FAULT); 
	} 

	st_pid = fork(); 
	if (st_pid < 0) { 
		perror("SIL_CGM_opt: fork(st refresh)"); 
		close(pfd[0]); 
		close(pfd[1]); 
		kill(ld_pid, SIGTERM); 
		waitpid(ld_pid, NULL, 0); 
		return SYS_FAULT; 
	} 

	if (st_pid == 0) { 
		if (dup2(pfd[0], STDIN_FILENO) < 0) {  
			perror("SIL_CGM_opt: dup2(st refresh)"); 
			_exit(EXE_FAULT); 
		} 
		close(pfd[0]); 
		close(pfd[1]); 
		execl(ST_BIN_PATH, ST_BIN_PATH, OUT_PATH, (char *) NULL); 
		perror("SIL_CGM_opt: execl(st refresh)"); 
		_exit(EXE_FAULT); 
	} 
	close(pfd[0]); 
	close(pfd[1]); 
	ld_status = 0; 
	st_status = 0; 

	if (waitpid(ld_pid, &ld_status, 0) < 0) { 
		perror("SIL_CGM_opt: waitpid(ld refresh)"); 
		return SYS_FAULT;
	} 

	if (waitpid(st_pid, &st_status, 0) < 0) { 
		perror("SIL_CGM_opt: waitpid(st refresh)"); 
		return SYS_FAULT; 
	} 

	if (!WIFEXITED(ld_status) || WEXITSTATUS(ld_status) != 0) 
		return SYS_FAULT; 

	if (!WIFEXITED(st_status) || WEXITSTATUS(st_status) != 0) 
		return SYS_FAULT; 

	return OK;
} 

int 
sil_cgm_opt(char *flag, char *cgroup_name, char **tgids, int tgid_count) { 
	pid_t pid; 
	int status; 

	if (!cgroup_name || !tgids || tgid_count <= 0) 
		return ARG_FAULT; 

	pid = fork(); 
	if (pid < 0) { 
		perror("SIL_CGM_opt: fork(setup)"); 
		return SYS_FAULT; 
	} 

	if (pid == 0) { 
		char *argv_setup[256]; 
		int i; 
		argv_setup[0] = (char *) SETUP_BIN_PATH; 
		argv_setup[1] = cgroup_name; 

		for (i = 0; i < tgid_count; i++) 
			argv_setup[i + 2] = tgids[i]; 

		argv_setup[tgid_count + 2] = NULL; 
		execv(SETUP_BIN_PATH, argv_setup); 
		perror("SIL_CGM_opt: execv(setup)"); 
		_exit(EXE_FAULT); 
	} 

	status = 0; 
	if (waitpid(pid, &status, 0) < 0) { 
		perror("SIL_CGM_opt: waitpid(setup)"); 
		return SYS_FAULT; 
	}  
	
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) 
		return SYS_FAULT; 
	
	pid = fork(); 
	
	if (pid < 0) {
		perror("SIL_CGM_opt: fork(attach)"); 
		return SYS_FAULT; 
	} 

	if (pid == 0) {
		if (!flag)
			execl(ATTACH_BIN_PATH, ATTACH_BIN_PATH, 
					cgroup_name, (char *) NULL); 
		else 
			execl(ATTACH_BIN_PATH, ATTACH_BIN_PATH, 
					flag, cgroup_name, (char *) NULL); 
		perror("SIL_CGM_opt: execl(attach)"); 
		_exit(EXE_FAULT); 
	} 

	status = 0; 
	if (waitpid(pid, &status, 0) < 0) { 
		perror("SIL_CGM_opt: waitpid(attach)");
		return SYS_FAULT;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return SYS_FAULT;

	return sil_cgm_refresh(flag, cgroup_name);
}

int
main(int argc, char **argv) { 
	char *flag; 
	char *cgroup_name; 
	char **tgids; 
	int tgid_count; 
	int refresh_only; 
	int argi; 
	
	flag = NULL; 
	cgroup_name = NULL; 
	tgids = NULL; 
	tgid_count = 0; 
	refresh_only = 0; 
	argi = 1; 
	
	while (argi < argc && argv[argi][0] == '-') { 
		if (strcmp(argv[argi], "-r") == 0) { 
			refresh_only = 1; 
		} else if (strcmp(argv[argi], "-l") == 0 ||  
				strcmp(argv[argi], "-g") == 0) { 
			if (flag) {
				fprintf(stderr, "Usage: %s"
						" [-r] [-l | -g]"
						" <cgroup-name>"
						" [TGID...]\n", 
						argv[0]);

				return ARG_FAULT;
			}

			flag = argv[argi];
		} else {
			fprintf(stderr, 
					"Usage: %s [-r] [-l | -g]"
					" <cgroup-name> [TGID...]\n", 
					argv[0]); 
			return ARG_FAULT; 
		} 
		argi++; 
	}

	if (argi >= argc) {
		fprintf(stderr,
			"Usage: %s [-r] [-l | -g]"
			" <cgroup-name> [TGID...]\n", 
			argv[0]);
		
		return ARG_FAULT;
	}

	cgroup_name = argv[argi++]; 
	if (!cgroup_name || *cgroup_name == '\0') {
		fprintf(stderr,
			"Usage: %s [-r] [-l | -g]" 
			" <cgroup-name> [TGID...]\n", 
			argv[0]); 
		return ARG_FAULT;
	}

	if (refresh_only) {
		if (argi != argc) {
			fprintf(stderr,
				"Usage: %s -r [-l | -g] <cgroup-name>\n",
				argv[0]);
			return ARG_FAULT;
		}
		return sil_cgm_refresh(flag, cgroup_name);
	}

	if (argi >= argc) {
		fprintf(stderr,
			"Usage: %s [-l | -g] <cgroup-name>"
			" <TGID> [TGID...]\n", 
			argv[0]); 
		return ARG_FAULT; 
	} 
	tgids = argv + argi; 
	tgid_count = argc - argi; 

	return sil_cgm_opt(flag, cgroup_name, tgids, tgid_count);
}
