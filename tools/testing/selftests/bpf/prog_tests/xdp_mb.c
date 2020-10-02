// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <linux/kernel.h>
#include <test_progs.h>
#include <network_helpers.h>

#include "test_xdp_multi_buff.skel.h"

static void test_xdp_mb_check_len(void)
{
	int test_sizes[] = { 128, 4096, 9000 };
	struct test_xdp_multi_buff *pkt_skel;
	__u8 *pkt_in = NULL, *pkt_out = NULL;
	__u32 duration = 0, retval, size;
	int err, pkt_fd, i;

	/* Load XDP program */
	pkt_skel = test_xdp_multi_buff__open_and_load();
	if (CHECK(!pkt_skel, "pkt_skel_load", "test_xdp_mb skeleton failed\n"))
		goto out;

	/* Allocate resources */
	pkt_out = malloc(test_sizes[ARRAY_SIZE(test_sizes) - 1]);
	pkt_in = malloc(test_sizes[ARRAY_SIZE(test_sizes) - 1]);
	if (CHECK(!pkt_in || !pkt_out, "malloc",
		  "Failed malloc, in = %p, out %p\n", pkt_in, pkt_out))
		goto out;

	pkt_fd = bpf_program__fd(pkt_skel->progs._xdp_check_mb_len);
	if (pkt_fd < 0)
		goto out;

	/* Run test for specific set of packets */
	for (i = 0; i < ARRAY_SIZE(test_sizes); i++) {
		int frags_count, j;

		for (j = 0; j < test_sizes[i]; j++)
			pkt_in[j] = j & 0xff;

		/* Run test program */
		err = bpf_prog_test_run(pkt_fd, 1, pkt_in, test_sizes[i],
					pkt_out, &size, &retval, &duration);

		if (CHECK(err || retval != XDP_PASS || size != test_sizes[i],
			  "test_run", "err %d errno %d retval %d size %d[%d]\n",
			  err, errno, retval, size, test_sizes[i]))
			goto out;

		/* Verify test results */
		frags_count = DIV_ROUND_UP(
			test_sizes[i] - pkt_skel->data->test_result_xdp_len,
			getpagesize());

		if (CHECK(pkt_skel->data->test_result_frags_count != frags_count,
			  "result", "frags_count = %llu != %u\n",
			  pkt_skel->data->test_result_frags_count, frags_count))
			goto out;

		if (CHECK(pkt_skel->data->test_result_frags_len != test_sizes[i] -
			  pkt_skel->data->test_result_xdp_len,
			  "result", "frags_len = %llu != %llu\n",
			  pkt_skel->data->test_result_frags_len,
			  test_sizes[i] - pkt_skel->data->test_result_xdp_len))
			goto out;

		for (j = 0; j < test_sizes[i]; j++) {
			if (CHECK(pkt_out[j] != (j & 0xff),
				  "content", "Packet content at offset %d is "
				  "wrong 0x%x != 0x%x\n",
				  j, pkt_out[j], j & 0xff))
				break;
		}
	}
out:
	if (pkt_out)
		free(pkt_out);
	if (pkt_in)
		free(pkt_in);

	test_xdp_multi_buff__destroy(pkt_skel);
}

static void test_xdp_mb_access(void)
{
	int test_sizes[] = { 128, 1500, 4096, 9000 };
	struct test_xdp_multi_buff *pkt_skel;
	__u8 *pkt_in = NULL, *pkt_out = NULL;
	__u32 duration = 0, retval, size;
	int err, pkt_fd, i;

	/* Load XDP program */
	pkt_skel = test_xdp_multi_buff__open_and_load();
	if (CHECK(!pkt_skel, "pkt_skel_load", "test_xdp_mb skeleton failed\n"))
		goto out;

	/* Allocate resources */
	pkt_out = malloc(test_sizes[ARRAY_SIZE(test_sizes) - 1]);
	pkt_in = malloc(test_sizes[ARRAY_SIZE(test_sizes) - 1]);
	if (CHECK(!pkt_in || !pkt_out, "malloc",
		  "Failed malloc, in = %p, out %p\n", pkt_in, pkt_out))
		goto out;

	pkt_fd = bpf_program__fd(pkt_skel->progs._xdp_mb_access);
	if (pkt_fd < 0)
		goto out;

	/* Run test for specific set of packets */
	for (i = 0; i < ARRAY_SIZE(test_sizes); i++) {
		int j;

		memset(pkt_in, 0, test_sizes[i]);

		/* Run test program */
		err = bpf_prog_test_run(pkt_fd, 1, pkt_in, test_sizes[i],
					pkt_out, &size, &retval, &duration);

		if (CHECK(err || retval != XDP_PASS || size != test_sizes[i],
			  "test_run", "err %d errno %d retval %d size %d[%d]\n",
			  err, errno, retval, size, test_sizes[i]))
			goto out;

		/* Verify test results */
		if (CHECK(!pkt_skel->data->test_result_current_frag,
			  "result_frag", "mb_frag test failed!\n"))
			goto out;

		for (j = 0; j < test_sizes[i]; j++) {
			if (CHECK(pkt_out[j] != (j & 0xff),
				  "content", "Packet content at offset %d is "
				  "wrong 0x%x != 0x%x\n",
				  j, pkt_out[j], j & 0xff))
				break;
		}
	}
out:
	if (pkt_out)
		free(pkt_out);
	if (pkt_in)
		free(pkt_in);

	test_xdp_multi_buff__destroy(pkt_skel);
}

static void test_xdp_mb_adjust_helpers(void)
{
	struct test_xdp_multi_buff *pkt_skel;
	int i, err, pkt_fd, test_size = 4096;
	__u8 *pkt_in = NULL, *pkt_out = NULL;
	__u32 duration = 0, retval, size;

	/* Load XDP program */
	pkt_skel = test_xdp_multi_buff__open_and_load();
	if (CHECK(!pkt_skel, "pkt_skel_load", "test_xdp_mb skeleton failed\n"))
		goto out;

	/* Allocate resources */
	pkt_out = malloc(test_size);
	pkt_in = malloc(test_size);
	if (CHECK(!pkt_in || !pkt_out, "malloc",
		  "Failed malloc, in = %p, out %p\n", pkt_in, pkt_out))
		goto out;

	pkt_fd = bpf_program__fd(pkt_skel->progs._xdp_mb_adjust_helpers);
	if (pkt_fd < 0)
		goto out;

	/* Select test to run */
	memset(pkt_in, 0, test_size);
	pkt_in[0] = 1; //TEST

	/* Run test program */
	err = bpf_prog_test_run(pkt_fd, 1, pkt_in, test_size,
				pkt_out, &size, &retval, &duration);


	switch (pkt_in[0]) {
	case 0:
		test_size -= 7;
		break;
	case 1:
		test_size -= 32 - 7;
		break;
	}

	if (CHECK(err || retval != XDP_PASS || size != test_size,
		  "test_run", "err %d errno %d retval %d size %d[%d]\n",
		  err, errno, retval, size, test_size))
		goto out;

	/* Verify test results */
	for (i = 0; i < test_size; i++) {
		if (CHECK(pkt_out[i] != (i & 0xff),
			  "content", "Packet content at offset %d is "
			  "wrong 0x%x != 0x%x\n",
			  i, pkt_out[i], i & 0xff))
			break;
	}
out:
	if (pkt_out)
		free(pkt_out);
	if (pkt_in)
		free(pkt_in);

	test_xdp_multi_buff__destroy(pkt_skel);
}

void test_xdp_mb(void)
{
	if (test__start_subtest("xdp_mb_check_len_frags"))
		test_xdp_mb_check_len();
	if (test__start_subtest("xdp_mb_access"))
		test_xdp_mb_access();
	if (test__start_subtest("xdp_mb_adjust_helpers"))
		test_xdp_mb_adjust_helpers();
}
