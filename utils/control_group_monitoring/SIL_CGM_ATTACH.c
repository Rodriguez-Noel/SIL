/* SIL_CGM_ATTACH.c
 *
 * Operation: Load CGM BPF skeleton, attach selected ingress/egress
 * cgroup_skb programs to a target cgroup, and pin only the relevant
 * maps/links for the chosen mode.
 *
 * Usage:
 *   SIL_CGM_ATTACH <cgroup-path> <mode> <pin-root>
 *
 */

#include "CGM.h" 
#include "CGM.bpf.h" 
#include "CGM.skel.h" 

#include <fcntl.h> 
#include <stdbool.h> 
#include <sys/stat.h> 
#include <sys/types.h> 

#include <bpf/libbpf.h> 
#include <bpf/bpf.h> 

#define PIN_ROOT "/sys/fs/bpf/sil" 
#define BASE "/sys/fs/cgroup" 

struct cgm_attach_plan { 
	enum cgm_mode mode;
	const char *mode_name;
	
	struct bpf_program *ingress_prog;
	struct bpf_program *egress_prog;
	
	struct bpf_map *maps[2];
	const char *map_names[2];
	size_t map_count;
	
	char mode_root[512]; 
	char maps_root[512]; 
	char links_root[512]; 
	char map_paths[2][512]; 
	char ingress_link_path[512]; 
	char egress_link_path[512];
}; 

struct cgm_attach_state { 
	struct CGM_bpf *skel; 
	struct bpf_link *ingress_link; 
	struct bpf_link *egress_link; 
	int cgroup_fd; 
	bool pinned_maps[2]; 
	bool pinned_ingress; 
	bool pinned_egress; 
}; 

void
sil_cgm_attach_usage(const char *argv0) { 
	fprintf(stderr, 
			"Usage: %s [-l | -g] <cgroup-name>\n" 
			"  -l  lean mode\n" 
			"  -g  greedy mode\n" 
			"  no flag = default mode\n", argv0); 
} 


int 
sil_cgm_attach_path(char *dst, size_t dsz, const char *a, const char *b) { 
	int tw; 
	
	if (!dst || dsz == 0 || !a || !b) 
		return ARG_FAULT; 
	
	tw = snprintf(dst, dsz, "%s/%s", a, b); 
	if (tw < 0 || tw >= (int)dsz) 
		return ARG_FAULT; 
	return OK; 
} 

int
sil_cgm_attach_path3(char *dst, size_t dsz, 
		const char *a, const char *b, const char *c) { 
	int tw; 
	
	if (!dst || dsz == 0 || !a || !b || !c) 
		return ARG_FAULT; 
	
	tw = snprintf(dst, dsz, "%s/%s/%s", a, b, c);
	if (tw < 0 || tw >= (int)dsz) 
		return ARG_FAULT; 
	return OK; 
} 

int 
sil_cgm_attach_fail_if_exists(const char *path) { 
	if (!path) 
		return ARG_FAULT; 
	
	if (access(path, F_OK) == 0) { 
		fprintf(stderr, "SIL_CGM_ATTACH: pin exists: %s\n", path); 
		return FAULT; 
	} 

	return OK; 
}
	
int 
sil_cgm_attach_build_plan(struct CGM_bpf *skel, enum cgm_mode mode, 
		const char *mode_name, const char *cgroup_name, 
		const char *pin_root, struct cgm_attach_plan *plan) { 
	int err; 
	size_t i;
	
	if (!skel || !mode_name || !pin_root || !plan) 
		return ARG_FAULT; 
	
	memset(plan, 0, sizeof(*plan)); 

	if (!cgroup_name || *cgroup_name == '\0') 
		return ARG_FAULT; 
	
	err = snprintf(plan->mode_root, sizeof(plan->mode_root), 
			"%s/cgm/%s/%s", pin_root, mode_name, cgroup_name); 
	
	if (err < 0 || err >= (int)sizeof(plan->mode_root)) 
		return ARG_FAULT; 
	
	switch (mode) { 
		case LEAN: 
			plan->ingress_prog = skel->progs.LEAN_CGM_INGRESS; 
			plan->egress_prog = skel->progs.LEAN_CGM_EGRESS; 
			plan->maps[0] = skel->maps.lean_cgm_map; 
			plan->map_names[0] = "lean_cgm_map"; 
			plan->map_count = 1; 
			break; 

		case DEFAULT: 
			plan->ingress_prog = skel->progs.CGM_INGRESS; 
			plan->egress_prog = skel->progs.CGM_EGRESS; 
			plan->maps[0] = skel->maps.cgm_map_a; 
			plan->map_names[0] = "cgm_map_a"; 
			plan->maps[1] = skel->maps.cgm_map_b; 
			plan->map_names[1] = "cgm_map_b"; 
			plan->map_count = 2; 
			break; 

		case GREEDY: 
			plan->ingress_prog = skel->progs.GREEDY_CGM_INGRESS; 
			plan->egress_prog = skel->progs.GREEDY_CGM_EGRESS; 
			plan->maps[0] = skel->maps.greedy_cgm_map; 
			plan->map_names[0] = "greedy_cgm_map"; 
			plan->map_count = 1;
			break; 
		
		default: 
			return ARG_FAULT;
	} 
	
	err = sil_cgm_attach_path(plan->maps_root, sizeof(plan->maps_root), 
			plan->mode_root, "maps"); 
	
	if (err) 
		return err; 
	
	err = sil_cgm_attach_path(plan->links_root, 
			sizeof(plan->links_root), 
			plan->mode_root, "links"); 
	if (err) 
		return err; 

	for (i = 0; i < plan->map_count; i++) { 
		err = sil_cgm_attach_path(plan->map_paths[i], 
				sizeof(plan->map_paths[i]), 
				plan->maps_root, plan->map_names[i]); 
		
		if (err) 
			return err; 
	} 

	err = sil_cgm_attach_path(plan->ingress_link_path, 
			sizeof(plan->ingress_link_path), 
			plan->links_root, "ingress"); 

	if (err) 
		return err; 
	
	err = sil_cgm_attach_path(plan->egress_link_path, 
			sizeof(plan->egress_link_path), 
			plan->links_root, "egress"); 
	
	if (err) 
		return err; 
	
	return OK; 
}
	
int
sil_cgm_attach_prepare_dirs(const struct cgm_attach_plan *plan) { 
	int err; 

	if (!plan) 
		return ARG_FAULT; 
	
	err = sil_mkdir_p(plan->mode_root);
	
	if (err) 
		return err; 
	
	err = sil_mkdir_p(plan->maps_root); 

	if (err) 
		return err;
	
	err = sil_mkdir_p(plan->links_root); 

	if (err)	
		return err; 
	
	return OK; 
}
	
int
sil_cgm_attach_validate_pins(const struct cgm_attach_plan *plan) {
	int err; 
	if (!plan)
		return ARG_FAULT;
	
	for (size_t i = 0; i < plan->map_count; i++) {
		err = sil_cgm_attach_fail_if_exists(plan->map_paths[i]);
		
		if (err) 
			return err;
	}
	
	err = sil_cgm_attach_fail_if_exists(plan->ingress_link_path);
	
	if (err) 
		return err; 

	err = sil_cgm_attach_fail_if_exists(plan->egress_link_path); 
	
	if (err) 
		return err;
	
	return OK;
}
	
int 
sil_cgm_attach_open_cgroup(const char *cgroup_path, int *fd_out) { 
	int fd; 

	if (!cgroup_path || *cgroup_path == '\0' || !fd_out) 
		return ARG_FAULT; 
	
	fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC); 
	
	if (fd < 0) { 
		perror("SIL_CGM_ATTACH: open cgroup"); 
		return SYS_FAULT; 
	} 
	
	*fd_out = fd;
	return OK;
} 
	
int 
sil_cgm_attach_open_load(struct CGM_bpf **skel_out) { 
	struct CGM_bpf *skel; 
	
	if (!skel_out) 
		return ARG_FAULT; 

	skel = CGM_bpf__open();
	if (!skel) { 
		fprintf(stderr, "SIL_CGM_ATTACH: CGM_bpf__open\n");
		return FAULT; 
	} 

	if (CGM_bpf__load(skel)) { 
		fprintf(stderr, "SIL_CGM_ATTACH: CGM_bpf__load\n"); 
		CGM_bpf__destroy(skel); 
		return FAULT;
	} 

	*skel_out = skel; 
	return OK; 
} 
	
int 
sil_cgm_attach_links(struct cgm_attach_state *state, 
		const struct cgm_attach_plan *plan) { 
	long err;

	if (!state || !plan) 
		return ARG_FAULT; 
	
	state->ingress_link = bpf_program__attach_cgroup(plan->ingress_prog,
			state->cgroup_fd);

	err = libbpf_get_error(state->ingress_link); 
	if (err) { 
		state->ingress_link = NULL; 
		fprintf(stderr, "SIL_CGM_ATTACH: ingress attach\n"); 
		return FAULT; 
	} 
	
	state->egress_link = bpf_program__attach_cgroup(plan->egress_prog, 
			state->cgroup_fd); 

	err = libbpf_get_error(state->egress_link);
	if (err) {  
		state->egress_link = NULL; 
		fprintf(stderr, "SIL_CGM_ATTACH: egress attach\n"); 
		return FAULT;
	} 
	
	return OK;
} 
	
int 
sil_cgm_attach_pin_maps(struct cgm_attach_state *state, 
		const struct cgm_attach_plan *plan) { 
	int err; 
	size_t i;

	if (!state || !plan) 
		return ARG_FAULT; 
	
	for (i = 0; i < plan->map_count; i++) { 
		err = bpf_map__pin(plan->maps[i], plan->map_paths[i]);
		
		if (err) {
			fprintf(stderr, "SIL_CGM_ATTACH: map pin: %s\n",
					plan->map_paths[i]);
			return FAULT;
		} 
		
		state->pinned_maps[i] = true; 
	} 
	
	return OK; 
}
	
int
sil_cgm_attach_pin_links(struct cgm_attach_state *state, 
		const struct cgm_attach_plan *plan) {
	int err; 

	if (!state || !plan) 
		return ARG_FAULT; 

	err = bpf_link__pin(state->ingress_link, plan->ingress_link_path); 
	if (err) { 
		fprintf(stderr, "SIL_CGM_ATTACH: ingress link pin\n"); 
		return FAULT; 
	} 

	state->pinned_ingress = true; 

	err = bpf_link__pin(state->egress_link, plan->egress_link_path); 
	if (err) { 
		fprintf(stderr, "SIL_CGM_ATTACH: egress link pin\n"); 
		return FAULT; 
	} 
	
	state->pinned_egress = true; 
	
	return OK; 
} 

void 
sil_cgm_attach_rollback(const struct cgm_attach_plan *plan, 
		struct cgm_attach_state *state) { 
	size_t i;

	if (!plan || !state) 
		return; 

	if (state->pinned_egress)
		unlink(plan->egress_link_path); 

	if (state->pinned_ingress) 
		unlink(plan->ingress_link_path); 
	
	for (i = 0; i < plan->map_count; i++) { 
		if (state->pinned_maps[i])
			unlink(plan->map_paths[i]);
	} 

	if (state->egress_link) 
		bpf_link__destroy(state->egress_link);
	
	if (state->ingress_link) 
		bpf_link__destroy(state->ingress_link); 

	if (state->skel) 
		CGM_bpf__destroy(state->skel); 

	if (state->cgroup_fd >= 0) 
		close(state->cgroup_fd);
}
	
int
main(int argc, char **argv) { 
	enum cgm_mode mode; 
	const char *mode_name; 
	const char *cgroup_name;
	char slice[256]; 
	char cgroup_path[512]; 
	struct cgm_attach_plan plan; 
	struct cgm_attach_state state; 
	int err; 
	size_t i;

	memset(&plan, 0, sizeof(plan)); 
	memset(&state, 0, sizeof(state));
	state.cgroup_fd = -1; 
	
	mode = DEFAULT; 
	mode_name = "default"; 
	cgroup_name = NULL; 
	
	if (argc == 2) { 
		cgroup_name = argv[1]; 
	} else if (argc == 3) { 
		if (strcmp(argv[1], "-l") == 0) { 
			mode = LEAN; 
			mode_name = "lean"; 
		} else if (strcmp(argv[1], "-g") == 0) { 
			mode = GREEDY; 
			mode_name = "greedy"; 
		} else { 
			sil_cgm_attach_usage(argv[0]); 
			return ARG_FAULT; 
		} 
		cgroup_name = argv[2]; 
	} else { 
		sil_cgm_attach_usage(argv[0]); 
		return ARG_FAULT; 
	} 
	
	if (!cgroup_name || *cgroup_name == '\0') { 
		sil_cgm_attach_usage(argv[0]); 
		return ARG_FAULT; 
	} 

	if (sil_r_cgroup_slice(slice, sizeof(slice))) { 
		fprintf(stderr, "SIL_CGM_ATTACH: sil_r_cgroup_slice\n"); 
		return FAULT;
	}
	
	err = snprintf(cgroup_path, sizeof(cgroup_path), 
			"%s%s/sil/%s", BASE, slice, cgroup_name); 
	if (err < 0 || err >= (int)sizeof(cgroup_path)) { 
		fprintf(stderr, "SIL_CGM_ATTACH: string\n"); 
		return ARG_FAULT; 
	} 
	
	err = sil_cgm_attach_open_load(&state.skel); 
	if (err) 
		return err; 
	
	err = sil_cgm_attach_build_plan(state.skel, mode, mode_name, 
			cgroup_name, PIN_ROOT, &plan); 
	if (err) 
		goto fail; 
	err = sil_cgm_attach_prepare_dirs(&plan); 
	if (err) 
		goto fail; 
	err = sil_cgm_attach_validate_pins(&plan); 
	if (err) 
		goto fail; 
	err = sil_cgm_attach_open_cgroup(cgroup_path, &state.cgroup_fd); 
	if (err) 
		goto fail; 
	err = sil_cgm_attach_links(&state, &plan); 
	if (err) 
		goto fail; 
	err = sil_cgm_attach_pin_maps(&state, &plan); 
	if (err) 
		goto fail; 
	err = sil_cgm_attach_pin_links(&state, &plan);  
	if (err) 
		goto fail;

	fprintf(stdout, "SIL_CGM_ATTACH: attached mode=%s\n", mode_name);
	fprintf(stdout, "  cgroup: %s\n", cgroup_path); 

	for (i = 0; i < plan.map_count; i++) 
		fprintf(stdout, "  map: %s\n", plan.map_paths[i]); 

	fprintf(stdout, "  ingress link: %s\n", plan.ingress_link_path); 
	fprintf(stdout, "  egress link: %s\n", plan.egress_link_path); 
	
	if (state.egress_link) 
		bpf_link__destroy(state.egress_link); 
	if (state.ingress_link) 
		bpf_link__destroy(state.ingress_link); 
	if (state.skel) 
		CGM_bpf__destroy(state.skel); 
	if (state.cgroup_fd >= 0) 
		close(state.cgroup_fd); 

	return OK;

fail: 
	sil_cgm_attach_rollback(&plan, &state); 
	return err;

}
