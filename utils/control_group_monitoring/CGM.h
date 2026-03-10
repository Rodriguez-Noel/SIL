/* CGM.h
 *
 * +------------------------------------------------------------+
 * | Operations: 						|
 * |- Retrieve user's cgroup path from /proc/self/cgroup	|SETUP
 * |- Build sub-tree: /sys/fs/cgroup/<slice>/sil/<CGM Target>	|SETUP
 * |- Write TGIDs to .../<CGM Target>/cgroup.procs placing it   |SETUP
 * |in the cgroup where a bpf program can then be attached.	|SETUP
 * |------------------------------------------------------------|
 * |- Validate path to target cgroup.				|ATTACH
 * |- Attach bpf program skb to target cgroup.			|ATTACH
 * |- Pin map for later reads.					|ATTACH
 * |------------------------------------------------------------|
 * |- Load data from pinned map through key walk. 		|LD 
 * |- Emit data in TSV format to STDOUT. (will be piped to an 	|LD
 * |ST program before reaching final destination.)		|LD
 * |------------------------------------------------------------| 
 * |- Create file in application's corresponding data dir. 	|ST
 * |- Read from STDIN and write that TSV data to file.		|ST
 * |------------------------------------------------------------| 
 * |- Call setup and attach binaries in preparation for LD & ST |opt
 * |operations.							|opt  
 * |- Pipe out from LD -> ST. Using fork,dup2,execl pattern.	|opt
 * +------------------------------------------------------------+
 *
 * Related files: SIL_CGM_SETUP, CGM_LIB, SIL_CGM_ATTACH, SIL_CGM_LD,
 * SIL_CGM_ST.
 *
 * Relationships:
 * --- Caller
 * <___ Dependency	^ Orchestration Layer
 * -------------------- | ------------------------------------------------
 * CGM Opt Suite:	|	
 * 		+---------------+
 *  		| SIL_CGM_opt.c	|
 *  		+---------------+
 * 			^ Option Layer 
 * -------------------- | ------------------------------------------------ 
 * CGM Util Suite:	|
 * 			+-------+-----------------------+-----------------+
 *  			|	|			|		  |
 *  	+---------------+	+----------------+	+---------------+ |
 *  	|SIL_CGM_SETUP.c|	|SIL_CGM_ATTACH.c|	| SIL_CGM_LD.c	| |
 *  	+---------------+	+----------------+   __>+---------------+ |
 *		       ^	^ 		    |			  |
 *		       |________|		    |			  |
 *	+-----------+  |  +-------+_________________|   +---------------+-+
 *	| CGM_LIB.c |__|__| CGM.h |			| SIL_CGM_ST.c	|
 *	+-----------+  |  +-------+  __________________>+---------------+
 *		       |____________|
 * -----------------------------------------------------------------------
 *  			BPF Layer
 * Last Updated 03/10/2026
 * Author: Noel Rodriguez
 */

#ifndef CGM_H
#define CGM_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

//Defined in CGM_LIB.c:
int sil_mkdir_p(const char *path); // Copy of mkdir -p from PS files.
int sil_r_cgroup_slice (char *buf, size_t bufsz);
/*----------------------------------------------------------------------*/

enum exits {
	OK = 0,
	FAULT = 1,
	ARG_FAULT = 2,
	SYS_FAULT = 3,
	ORC_FAULT = 4,
	PRM_FAULT = 5,
	EXE_FAULT = 127
};

#endif
