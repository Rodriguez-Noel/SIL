/* OPT.h
 *
 * +--------------------------------------------------------------------+
 * | Operations:							|
 * +--------------------------------------------------------------------+
 * | - SIL_PS_opt.c (Process Snapshot):					|
 * | When given a path, write to file tab separated values: 		|
 * | PID\tTGID\tUID\tThreads\tCOMM					|
 * +--------------------------------------------------------------------+
 * | - SIL_CGM_opt.c (Control Group Monitoring): N/A			|
 * +--------------------------------------------------------------------+
 *
 * Related Files: SIL_PS_opt.c, SIL_CGM_opt.c
 * Type: Header
 *
 * Relationships:
 * ---- Caller
 * <=== Dependency
 *			^ Orchestration Layer
 * --------------------	| ------------------------------------------------
 * Option Suite:	+-----------------------+ 
 * 			|			|
 * 	+---------------+	+-------+	+---------------+
 * 	| SIL_PS_opt.c	|<======| OPT.h	|======>| SIL_CGM_opt.c	|
 * 	+---------------+	+-------+	+---------------+
 * -----^---------------------------------------^-------------------------
 *	|					|
 *      +------	Utility Layer-------------------+
 * -----------------------------------------------------------------------
 *  		BPF Layer
 * -----------------------------------------------------------------------
 *
 * Last Updated: 03/08/2026
 * Author: Noel Rodriguez
 */

#ifndef OPT_H
#define OPT_H

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
