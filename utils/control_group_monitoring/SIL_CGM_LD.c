/* SIL_CGM_LD.c
 *
 * Operation: Load pinned CGM telemetry map data to STDOUT in TSV format.
 * Type: Atomic - this binary should not be interrupted unless it fails.
 *
 * See CGM.h for additional information.
 */

#include "CGM.h"
#include "CGM.bpf.h"

#include <bpf/bpf.h>

#define PIN_ROOT "/sys/fs/bpf/sil" 
#define BASE "/sys/fs/cgroup" 

int sil_cgm_ld_open_map(char *path, int *fd_out);
int sil_cgm_ld_emit_lean(int map_fd);
int sil_cgm_ld_emit_default_a(int map_fd);
int sil_cgm_ld_emit_default_b(int map_fd);
int sil_cgm_ld_emit_greedy(int map_fd);
int sil_cgm_ld(char *pin_root, enum cgm_mode mode, 
		char *mode_name, char *cgroup_name);

int 
sil_cgm_ld_open_map(char *path, int *fd_out) { 
	int fd; 
	if (!path || !fd_out) 
		return ARG_FAULT; 
	fd = bpf_obj_get(path); 

	if (fd < 0) { 
		fprintf(stderr, "SIL_CGM_LD: bpf_obj_get\n: %s\n", 
				strerror(errno)); 
		return SYS_FAULT;
	} 
	
	*fd_out = fd; 
	return OK; 
} 
int 
sil_cgm_ld_emit_lean(int map_fd) { 
	struct lean_cgm_key key; 
	struct lean_cgm_key next; 
	struct cgm_totals val; 
	int first; 
	first = 1;
	
	for (;;) { 
		if (bpf_map_get_next_key(map_fd, 
					first ? NULL : &key, &next) != 0) {
			if (errno == ENOENT) 
				return OK; 
			fprintf(stderr, "SIL_CGM_LD: bpf_map_get_next_key"
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT; 
		} 
		if (bpf_map_lookup_elem(map_fd, &next, &val) != 0) { 
			fprintf(stderr, "SIL_CGM_LD: bpf_map_lookup_elem"
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT; 
		} 

		printf("LEAN\t%u\t%llu\t%llu\t%llu\t%llu\n", 
				(unsigned) next.tgid, 
				(unsigned long long) val.in_packets, 
				(unsigned long long) val.in_bytes, 
				(unsigned long long) val.out_packets, 
				(unsigned long long) val.out_bytes); 
		key = next; 
		first = 0; 
	} 
} 

int 
sil_cgm_ld_emit_default_a(int map_fd) { 
	struct cgm_key_a key; 
	struct cgm_key_a next; 
	struct cgm_totals val; 
	int first; 

	first = 1; 
	
	for (;;) { 
		if (bpf_map_get_next_key(map_fd, 
					first ? NULL : &key, &next) != 0) {

			if (errno == ENOENT) 
				return OK; 

			fprintf(stderr, "SIL_CGM_LD: bpf_map_get_next_key"
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT; 
		} 

		if (bpf_map_lookup_elem(map_fd, &next, &val) != 0) { 
			fprintf(stderr, "SIL_CGM_LD: bpf_map_lookup_elem"
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT; 
		} 

		printf("DEFAULT_A\t%u\t%u\t%u\t%llu\t%llu\t%llu\t%llu\n", 
				(unsigned) next.tgid, 
				(unsigned) next.ipv, 
				(unsigned) next.protocol, 
				(unsigned long long) val.in_packets, 
				(unsigned long long) val.in_bytes, 
				(unsigned long long) val.out_packets, 
				(unsigned long long) val.out_bytes); 
		key = next; 
		first = 0; 
	} 
} 

int 
sil_cgm_ld_emit_default_b(int map_fd) { 
	struct cgm_key_b key; 
	struct cgm_key_b next; 
	struct cgm_totals val; 
	int first; 

	first = 1; 

	for (;;) { 

		if (bpf_map_get_next_key(map_fd, 
					first ? NULL : &key, &next) != 0) {
			if (errno == ENOENT) 
				return OK; 

			fprintf(stderr, "SIL_CGM_LD: bpf_map_get_next_key" 
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT; 
		} 
		
		if (bpf_map_lookup_elem(map_fd, &next, &val) != 0) { 
			fprintf(stderr, "SIL_CGM_LD: bpf_map_lookup_elem"
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT; 
		} 

		printf("DEFAULT_B\t%u\t%u\t%u\t%u\t%llu"
				"\t%llu\t%llu\t%llu\n", 
				(unsigned) next.tgid, 
				(unsigned) next.protocol, 
				(unsigned) next.sport, 
				(unsigned) next.dport, 
				(unsigned long long) val.in_packets, 
				(unsigned long long) val.in_bytes, 
				(unsigned long long) val.out_packets, 
				(unsigned long long) val.out_bytes); 
		key = next; 
		first = 0; 
	} 
} 

int  
sil_cgm_ld_emit_greedy(int map_fd) { 
	struct greedy_cgm_key key; 
	struct greedy_cgm_key next; 
	struct cgm_totals val; 
	int first; 

	first = 1; 
	for (;;) { 
		if (bpf_map_get_next_key(map_fd, 
					first ? NULL : &key, &next) != 0) {

			if (errno == ENOENT) 
				return OK; 

			fprintf(stderr, "SIL_CGM_LD: bpf_map_get_next_key"
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT;
		}  

		if (bpf_map_lookup_elem(map_fd, &next, &val) != 0) { 
			fprintf(stderr, "SIL_CGM_LD: bpf_map_lookup_elem"
					"\n: %s\n", strerror(errno)); 

			return SYS_FAULT; 
		} 

		printf("GREEDY\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u"
				"\t%u\t%u\t%u\t%u\t%u\t%llu\t%llu"
				"\t%llu\t%llu\n", 
				(unsigned) next.tgid, 
				(unsigned) next.ipv, 
				(unsigned) next.protocol, 
				(unsigned) next.sport, 
				(unsigned) next.dport, 
				(unsigned) next.saddr[0], 
				(unsigned) next.saddr[1], 
				(unsigned) next.saddr[2], 
				(unsigned) next.saddr[3], 
				(unsigned) next.daddr[0], 
				(unsigned) next.daddr[1], 
				(unsigned) next.daddr[2], 
				(unsigned) next.daddr[3], 
				(unsigned long long) val.in_packets, 
				(unsigned long long) val.in_bytes, 
				(unsigned long long) val.out_packets, 
				(unsigned long long) val.out_bytes); 
		key = next; 
		first = 0; 
	} 
} 

int
sil_cgm_ld(char *pin_root, enum cgm_mode mode, 
		char *mode_name, char *cgroup_name) { 
	char map_a_path[512]; 
	char map_b_path[512]; 
	int map_fd_a; 
	int map_fd_b; 
	int tw; 
	int err;
	
	if (!pin_root || !mode_name) 
		return ARG_FAULT; 
	map_fd_a = -1; 
	map_fd_b = -1; 
	switch (mode) { 
		case LEAN:
			tw = snprintf(map_a_path, sizeof(map_a_path),
					"%s/cgm/%s/%s/maps/lean_cgm_map",
					pin_root, mode_name, cgroup_name);
			if (tw < 0 || tw >= (int)sizeof(map_a_path))
				return ARG_FAULT;

			err = sil_cgm_ld_open_map(map_a_path, &map_fd_a);
			if (err)
				return err;

			err = sil_cgm_ld_emit_lean(map_fd_a);
			close(map_fd_a);
			return err;

		case DEFAULT:
			tw = snprintf(map_a_path, sizeof(map_a_path), 
					"%s/cgm/%s/%s/maps/cgm_map_a", 
					pin_root, mode_name, cgroup_name); 
			if (tw < 0 || tw >= (int) sizeof(map_a_path)) 
				return ARG_FAULT; 
			tw = snprintf(map_b_path, sizeof(map_b_path), 
					"%s/cgm/%s/%s/maps/cgm_map_b", 
					pin_root, mode_name, cgroup_name); 
			if (tw < 0 || tw >= (int) sizeof(map_b_path)) 
				return ARG_FAULT; 
			err = sil_cgm_ld_open_map(map_a_path, &map_fd_a); 

			if (err) 
				return err; 
			err = sil_cgm_ld_open_map(map_b_path, &map_fd_b); 
			
			if (err) { 
				close(map_fd_a); 
				return err;
			} 
			
			err = sil_cgm_ld_emit_default_a(map_fd_a);
			
			if (!err) 
				err = sil_cgm_ld_emit_default_b(map_fd_b);
			
			close(map_fd_b); 
			close(map_fd_a);
			
			return err;
		
		case GREEDY: 
			tw = snprintf(map_a_path, sizeof(map_a_path),
					"%s/cgm/%s/%s/maps/greedy_cgm_map",
					pin_root, mode_name, cgroup_name);
			if (tw < 0 || tw >= (int)sizeof(map_a_path))
				return ARG_FAULT;

			err = sil_cgm_ld_open_map(map_a_path, &map_fd_a);
			if (err)
				return err;

			err = sil_cgm_ld_emit_greedy(map_fd_a);
			close(map_fd_a);
			return err;	

		default: 
			return ARG_FAULT;
	} 
} 

int 
main(int argc, char **argv) { 
	enum cgm_mode mode; 
	char *mode_name; 
	char *cgroup_name;

	mode = DEFAULT; 
	mode_name = "default"; 
	cgroup_name = NULL;

	if (argc == 2){
		cgroup_name = argv[1];
	} else if (argc == 3) { 
		if (strcmp(argv[1], "-l") == 0) { 
			mode = LEAN; 
			mode_name = "lean";
       			cgroup_name = argv[2];	
		} else if (strcmp(argv[1], "-g") == 0) { 
			mode = GREEDY; 
			mode_name = "greedy"; 
			cgroup_name = argv[2];
		} else { 
			fprintf(stderr, "Usage: %s [-l | -g]"
					" <cgroup-name>\n", 
					argv[0]); 
		
			return ARG_FAULT; 
		} 

	} else { 
		fprintf(stderr, "Usage: %s [-l | -g]"
				" <cgroup-name>\n", 
				argv[0]); 
		
		return ARG_FAULT; 
	} 

	return sil_cgm_ld(PIN_ROOT, mode, mode_name, cgroup_name);
}
