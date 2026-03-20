/*
 *
 *
 *
 *
 *
 *
 */


#include "CGM.bpf.h" 

#include <linux/bpf.h> 
#include <linux/in.h> 
#include <linux/ip.h> 
#include <linux/ipv6.h> 
#include <linux/tcp.h> 
#include <linux/udp.h> 

/*TODO: Fix includes for AF_INET/AF_INET6*/
// TEMP SOLUTION 03/12/2026
#define AF_INET 2
#define AF_INET6 10

#include <bpf/bpf_helpers.h> 
#include <bpf/bpf_endian.h> 



enum returns { 
	OK = 0, 
	SKIP = -1 
}; 

struct { 
	__uint(type, BPF_MAP_TYPE_LRU_HASH); 
	__uint(max_entries, 1024); 
	__type(key, struct lean_cgm_key); 
	__type(value, struct cgm_totals); 
} lean_cgm_map SEC(".maps"); 

struct { 
	__uint(type, BPF_MAP_TYPE_LRU_HASH); 
	__uint(max_entries, 2048); 
	__type(key, struct cgm_key_a); 
	__type(value, struct cgm_totals); 
} cgm_map_a SEC(".maps"); 

struct { 
	__uint(type, BPF_MAP_TYPE_LRU_HASH); 
	__uint(max_entries, 2048); 
	__type(key, struct cgm_key_b); 
	__type(value, struct cgm_totals);
} cgm_map_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct greedy_cgm_key); 
	__type(value, struct cgm_totals); 
} greedy_cgm_map SEC(".maps"); 

struct cgm_mdata {
	__u32 tgid; 
	__u16 ipv; 
	__u8 protocol;
	__u16 sport; 
	__u16 dport; 
	__u64 len;
	__u32 saddr[4]; 
	__u32 daddr[4];
}; 

static __always_inline __u32 
cgm_tgid(void) { 
	return (__u32)(bpf_get_current_pid_tgid() >> 32); 
} 

static void 
cgm_add_in(struct cgm_totals *v, __u64 len) {
	__sync_fetch_and_add(&v->in_packets, 1);
	__sync_fetch_and_add(&v->in_bytes, len);
} 

static void
cgm_add_out(struct cgm_totals *v, __u64 len) { 
	__sync_fetch_and_add(&v->out_packets, 1); 
	__sync_fetch_and_add(&v->out_bytes, len);
}

static __always_inline int
cgm_parse_mdata(struct __sk_buff *skb, struct cgm_mdata *m) { 
	void *data; 
	void *data_end; 
	__u8 version; 
	__u8 jmp; 
	__u8 tmp; 
	char *hdr; 

	data = (void *) (long)skb->data; 
	data_end = (void *) (long)skb->data_end; 

	if (data + 1 > data_end) 
		return SKIP; 
	
	version = (*(__u8 *)data) >> 4; 
	
	m->tgid = cgm_tgid(); 
	m->len = (__u64)skb->len; 
	
	if (version != 4 && version != 6) 
		return SKIP; 

	jmp = (version >> 1) - 2; 
	switch (jmp) { 
		case 0: { 
				struct iphdr *iph; 
				iph = data; 
				__u32 ihl_b; 
				if ((void *)(iph + 1) > data_end) 
					return SKIP; 

				ihl_b = (__u32)iph->ihl * 4; 
				if (ihl_b < sizeof(*iph)) 
					return SKIP; 

				if ((char *)iph + ihl_b > (char *)data_end) 
					return SKIP; 

				m->ipv = AF_INET; 
				m->protocol = iph->protocol; 
				m->saddr[0] = iph->saddr; 
				m->daddr[0] = iph->daddr; 

				hdr = (char *)iph + ihl_b; 
				tmp = iph->protocol; 

				if (hdr + 4 > (char *)data_end)
					return SKIP; 

				if (tmp != IPPROTO_TCP && 
						tmp != IPPROTO_UDP)
					return SKIP; 
				
				m->sport = bpf_ntohs(*(__be16 *) hdr); 
				m->dport = bpf_ntohs(*(__be16 *)(hdr + 2)); 
				return OK; 

			} 
		case 1: { 
				struct ipv6hdr *iph;
				iph = data; 
				
				if ((void *)(iph + 1) > data_end) 
					return SKIP; 
				
				m->ipv = AF_INET6; 
				m->protocol = iph->nexthdr; 
				
				__builtin_memcpy(m->saddr, &iph->saddr, 
						sizeof(iph->saddr)); 
				
				__builtin_memcpy(m->daddr, &iph->daddr,
						sizeof(iph->daddr)); 
				
				tmp = iph->nexthdr; 
				hdr = (char *)(iph + 1); 
				
				if (hdr + 4 > (char *) data_end) 
					return SKIP; 

				if (tmp != IPPROTO_TCP && 
						tmp != IPPROTO_UDP) 
					return SKIP;
								
				m->sport = bpf_ntohs(*(__be16 *)hdr); 
				m->dport = bpf_ntohs(*(__be16 *)(hdr + 2));

				return OK; 
			} 
		default: 
			return SKIP; 
	} 
}

static __always_inline struct cgm_totals *
cgm_update(void *map, const void *key) { 
	struct cgm_totals *v;
	struct cgm_totals zeroed = {0};

	v = bpf_map_lookup_elem(map, key); 
	if (v) 
		return v; 

	bpf_map_update_elem(map, key, &zeroed, BPF_NOEXIST);
	return bpf_map_lookup_elem(map, key); 
} 

static  __always_inline void
cgm_account(const struct cgm_mdata *m, __u32 mode, int ingress) { 
	if (mode == LEAN) {
	       struct lean_cgm_key key; 
	       struct cgm_totals *v; 

	       key.tgid = m->tgid; 
	       v = cgm_update(&lean_cgm_map, &key);

	       if (!v) 
		       return; 

	       if (ingress) 
		       cgm_add_in(v, m->len);
	       else
		       cgm_add_out(v, m->len); 
	       return;

	} 

	if (mode == DEFAULT) { 
		struct cgm_key_a key_a; 
		struct cgm_key_b key_b; 
		struct cgm_totals *val_a; 
		struct cgm_totals *val_b; 
		
		key_a.tgid = m->tgid; 
		key_a.ipv = m->ipv; 
		key_a.protocol = m->protocol; 

		key_b.tgid = m->tgid; 
		key_b.protocol = m->protocol; 
		key_b.sport = m->sport; 
		key_b.dport = m->dport; 

		val_a = cgm_update(&cgm_map_a, &key_a); 
		val_b = cgm_update(&cgm_map_b, &key_b); 

		if (val_a) { 
			if (ingress) 
				cgm_add_in(val_a, m->len); 
			else 
				cgm_add_out(val_a, m->len); 
		} 

		if (val_b) { 
			if (ingress) 
				cgm_add_in(val_b, m->len); 
			else 
				cgm_add_out(val_b, m->len); 
		} 
		
		return;
	}

	if (mode == GREEDY) { 
		struct greedy_cgm_key key;
		struct cgm_totals *v;

		key.tgid = m->tgid; 
		key.ipv = m->ipv; 
		key.protocol = m->protocol; 
		key.sport = m->sport; 
		key.dport = m->dport; 
		__builtin_memcpy(key.saddr, m->saddr, sizeof(key.saddr)); 
		__builtin_memcpy(key.daddr, m->daddr, sizeof(key.daddr)); 

		v = cgm_update(&greedy_cgm_map, &key); 
		if (!v)
			return;
		
		if (ingress)
			cgm_add_in(v, m->len); 
		else 
			cgm_add_out(v, m->len); 
	}
} 

static __always_inline int
cgm_handle(struct __sk_buff *skb, __u32 mode, int ingress) { 
	struct cgm_mdata m = {0}; 

	if (cgm_parse_mdata(skb, &m) == OK) 
		cgm_account(&m, mode, ingress); 

	return 1;
} 

SEC("cgroup_skb/ingress") 
int LEAN_CGM_INGRESS(struct __sk_buff *skb) { 
	return cgm_handle(skb, LEAN, 1); 
} 
SEC("cgroup_skb/egress") 
int LEAN_CGM_EGRESS(struct __sk_buff *skb) { 
	return cgm_handle(skb, LEAN, 0); 
} 
SEC("cgroup_skb/ingress") 
int CGM_INGRESS(struct __sk_buff *skb) {
	return cgm_handle(skb, DEFAULT, 1); 
} 

SEC("cgroup_skb/egress") 
int CGM_EGRESS(struct __sk_buff *skb) { 
	return cgm_handle(skb, DEFAULT, 0); 
} 
	
SEC("cgroup_skb/ingress") 
int GREEDY_CGM_INGRESS(struct __sk_buff *skb) { 
	return cgm_handle(skb, GREEDY, 1); 
}

SEC("cgroup_skb/egress") 
int GREEDY_CGM_EGRESS(struct __sk_buff *skb) { 
	return cgm_handle(skb, GREEDY, 0);
} 

char LICENSE[] SEC("license") = "GPL";
