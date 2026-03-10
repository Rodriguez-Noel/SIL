/* PS.h (Process Snapshot) 
 * 
 * +--------------------------------------------------------------------+
 * | Operations: 						 	|
 * |- Find active processes through ./proc.			 	|LD
 * |- Walk dir entries for process directories (pids). 		 	|LD
 * |- Check that the entry is a pid (all numeric). 		 	|LD
 * |- Capture thread group leaders by checking pid == tgid. 	 	|LD
 * |- Write to STDOUT.						 	|LD
 * |--------------------------------------------------------------------|
 * |- Validate/Setup path to intended writable file.		 	|ST
 * |- Read tsv from STDIN.					 	|ST
 * |- Write to filestream.					 	|ST
 * |--------------------------------------------------------------------|
 * |- Validate/Sanitize arguments/options.			 	|opt
 * |- Create pipe Write-end: LD | Read-end: ST			 	|opt
 * |- Execl binaries: LD->ST.					 	|opt
 * +--------------------------------------------------------------------+
 *
 * Related Files: SIL_PS_ST.c, SIL_PS_LD.c, SIL_PS_opt.c
 * Type: Header	
 *
 * Relationships:
 * ---> Caller / Uses Binary
 * <=== Dependency / Includes
 *
 * 			^ Orchestration Layer
 * -------------------- | --------------------------------------------------
 *  PS Opt Suite:	|
 * 	+-------+---------------+
 * 	|    SIL_PS_opt.c    	| Option Layer
 *	+-----------------------+<--------------+
 *				^		|
 * ---------------------------- | ------------- | --------------------------
 * PS Util Suite:	+-------+		|
 *			|			|
 *	+---------------+	+-------+	+---------------+
 *	|  SIL_PS_LD.c  |<======| PS.h	|======>|  SIL_PS_ST.c	| Util Layer
 *	+---------------+	+-------+	+---------------+
 * -------------------------------------------------------------------------
 *			BPF Layer
 * -------------------------------------------------------------------------
 * 
 * Last Updated 03/08/2026
 * Author: Noel Rodriguez
 */

#ifndef PS_H
#define PS_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
