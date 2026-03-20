#ifndef CGM_BPF_H
#define CGM_BPF_H

#include <linux/types.h>

enum cgm_mode {
	LEAN    = 0,
	DEFAULT = 1,
	GREEDY  = 2
};

struct cgm_totals {
	__u64 in_packets;
	__u64 in_bytes;
	__u64 out_packets;
	__u64 out_bytes;
};

struct lean_cgm_key {
	__u32 tgid;
};

struct cgm_key_a {
	__u32 tgid;
	__u16 ipv;
	__u8  protocol;
	__u8  padding;
};

struct cgm_key_b {
	__u32 tgid;
	__u8  protocol;
	__u8  padding;
	__u16 sport;
	__u16 dport;
	__u16 padding2;
};

struct greedy_cgm_key {
	__u32 tgid;
	__u16 ipv;
	__u8  protocol;
	__u8  padding;
	__u16 sport;
	__u16 dport;
	__u32 saddr[4];
	__u32 daddr[4];
};

#endif
