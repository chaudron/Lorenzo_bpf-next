// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

__u64 test_result_frags_count = UINT64_MAX;
__u64 test_result_frags_len = UINT64_MAX;
__u64 test_result_xdp_len = UINT64_MAX;
__u64 test_result_current_frag = UINT64_MAX;

SEC("xdp_check_mb_len")
int _xdp_check_mb_len(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;

	test_result_xdp_len = (__u64)(data_end - data);
	test_result_frags_len = bpf_xdp_get_frags_total_size(xdp);
	test_result_frags_count = bpf_xdp_get_frags_count(xdp);
	return XDP_PASS;
}


static __always_inline void fill_xdp_packet(struct xdp_md *xdp)
{
	__u8 *data_end = (void *)(long)xdp->data_end;
	__u8 *data = (void *)(long)xdp->data;
	int i, frag, frag_count, offset = 0;

	/* Overwrite non-fragment buffer. */
	for (i = 0; i < 4096; i++) {
		if (data + 1 <= data_end)
			*(data++) = i & 0xff;
		else
			break;
	}

	test_result_current_frag = 1;
	if (!xdp->mb)
		return;

	/* Do the additional fragments. */
	frag_count = bpf_xdp_get_frags_count(xdp);
	for (frag = 1; frag <= 4; frag++) {

		offset += i;

		if (frag > frag_count)
			break;

		bpf_xdp_set_current_frag(xdp, frag);

		if (xdp->mb_frag != frag)
			test_result_current_frag = 0;

		data_end = (unsigned char *)(long)xdp->data_end;
		data = (unsigned char *)(long)xdp->data;

		for (i = 0; i < 4096; i++) {
			if (data + 1 <= data_end)
				*(data++) = (i + offset) & 0xff;
			else
				break;
		}
	}
}

SEC("xdp_mb_access")
int _xdp_mb_access(struct xdp_md *xdp)
{
	fill_xdp_packet(xdp);
	return XDP_PASS;
}


SEC("xdp_mb_adjust_helpers")
int _xdp_mb_adjust_helpers(struct xdp_md *xdp)
{
	__u8 *data_end = (void *)(long)xdp->data_end;
	__u8 *data = (void *)(long)xdp->data;
	__u8 test;

	if (!xdp->mb)
		return XDP_DROP;

	if (data + 1 <= data_end)
		test = data[0];

	switch(test) {
	case 0:
		/* Make packet 7 bytes smaller by shrinking mb's head */
		bpf_xdp_set_current_frag(xdp, 1);
		bpf_xdp_adjust_head(xdp, 7);
		break;
	case 1:
		/* By default, there is no headroom, so we create some (32),
		 * assuming test 0 above is successful, then grow back 7 bytes.
		 */
		bpf_xdp_set_current_frag(xdp, 1);
		bpf_xdp_adjust_head(xdp, 32);
		bpf_xdp_adjust_head(xdp, -7);
		break;
	default:
		return XDP_DROP;
	}

	bpf_xdp_set_current_frag(xdp, 0);
	fill_xdp_packet(xdp);

	return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
