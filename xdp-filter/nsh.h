/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Minimal Network Service Header (NSH) definitions for BPF programs.
 * Based on RFC 8300.
 *
 * NSH Base Header + Service Path Header (8 bytes):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver|O|U|    TTL    |   Length  |U|U|U|U|MD Type| Next Protocol |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Service Path Identifier (SPI)        | Service Index |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#ifndef __NSH_H
#define __NSH_H

#include <bpf/bpf_endian.h>

#ifndef ETH_P_NSH
#define ETH_P_NSH 0x894F
#endif

/* Masking NSH path header fields. */
#define NSH_SPI_MASK       0xffffff00
#define NSH_SPI_SHIFT      8
#define NSH_SI_MASK        0x000000ff
#define NSH_SI_SHIFT       0

/* Minimal NSH base header for BPF processing.
 * Only includes the fixed 8-byte base + service path header.
 */
struct nshhdr {
	__be16 ver_flags_ttl_len;
	__u8 mdtype;
	__u8 np;
	__be32 path_hdr;
};

/*
 * nsh_dec_si - Decrement the Service Index (SI) in an NSH header.
 *
 * The SI field occupies the lowest 8 bits of the path_hdr word.
 * Per RFC 8300, the SI MUST be decremented by 1 by Service Functions
 * after performing required services.
 *
 * @nh:       header cursor positioned at the start of the NSH header
 * @data_end: end of packet data for bounds checking
 *
 * Returns 0 on success, -1 if the NSH header cannot be parsed.
 */
static __always_inline int nsh_dec_si(struct hdr_cursor *nh, void *data_end)
{
	struct nshhdr *nsh = nh->pos;

	if ((void *)(nsh + 1) > data_end)
		return -1;

	__u32 path_host = bpf_ntohl(nsh->path_hdr);
	__u8 si = path_host & NSH_SI_MASK;

	if (si > 0)
		nsh->path_hdr = bpf_htonl((path_host & NSH_SPI_MASK) | (si - 1));

	return 0;
}

#endif /* __NSH_H */
