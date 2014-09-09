/*
%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
*/

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "erl_nif.h"

#include "bitmap.h"

static ERL_NIF_TERM
uncompress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary in, out, temp;
	ERL_NIF_TERM err;
	int ret, w, h;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	memset(&temp, 0, sizeof(temp));

	if (!enif_inspect_binary(env, argv[0], &in)) {
		err = enif_make_atom(env, "bad_data");
		goto fail;
	}
	if (!enif_get_int(env, argv[1], &w)) {
		err = enif_make_atom(env, "bad_width");
		goto fail;
	}
	if (!enif_get_int(env, argv[2], &h)) {
		err = enif_make_atom(env, "bad_height");
		goto fail;
	}

	assert(enif_alloc_binary(w*h*4, &out));

	ret = bitmap_decompress(in.data, out.data, w, h, in.size, 24, 32);

	if (ret <= 0) {
		err = enif_make_atom(env, "decompress_failure");
		goto fail;
	}

	/*assert(enif_alloc_binary(w*h*4, &out));
	for (i = 0, j = 0; i < w*h; ++i, j += 3) {
		uint32_t k = 0;
		k |= temp.data[j];
		k |= temp.data[j+1] << 8;
		k |= temp.data[j+2] << 16;
		((uint32_t *)out.data)[i] = k;
	}

	enif_release_binary(&temp);*/

	return enif_make_tuple2(env,
		enif_make_atom(env, "ok"),
		enif_make_binary(env, &out));
fail:
	if (out.data != NULL)
		enif_release_binary(&out);
	return enif_make_tuple2(env,
		enif_make_atom(env, "error"), err);
}

static ERL_NIF_TERM
compress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary in;
	ERL_NIF_TERM err;
	int w, h, ret;
	struct stream out, temp;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	memset(&temp, 0, sizeof(temp));

	if (!enif_inspect_binary(env, argv[0], &in)) {
		err = enif_make_atom(env, "bad_data");
		goto fail;
	}
	if (!enif_get_int(env, argv[1], &w)) {
		err = enif_make_atom(env, "bad_width");
		goto fail;
	}
	if (!enif_get_int(env, argv[2], &h)) {
		err = enif_make_atom(env, "bad_height");
		goto fail;
	}
	if (in.size != w*h*4) {
		err = enif_make_atom(env, "bad_size");
		goto fail;
	}

	assert(enif_alloc_binary(128*1024, &out.bin));
	assert(enif_alloc_binary(128*1024, &temp.bin));

	ret = xrdp_bitmap_compress((char *)in.data, w, h,
		&out, 24, 128*1024, &temp);
	if (ret <= 0) {
		err = enif_make_atom(env, "no_lines_sent");
		goto fail;
	}
	fprintf(stderr, "returning %d lines\n", ret);

	enif_release_binary(&temp.bin);
	assert(enif_alloc_binary(out.pos, &temp.bin));
	memcpy(temp.bin.data, out.bin.data, out.pos);
	enif_release_binary(&out.bin);

	return enif_make_tuple2(env,
		enif_make_atom(env, "ok"),
		enif_make_binary(env, &temp.bin));

fail:
	if (out.bin.data != NULL)
		enif_release_binary(&out.bin);
	if (temp.bin.data != NULL)
		enif_release_binary(&temp.bin);
	return enif_make_tuple2(env,
		enif_make_atom(env, "error"), err);
}

static int
load_cb(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	return 0;
}

static void
unload_cb(ErlNifEnv *env, void *priv_data)
{
}

static ErlNifFunc nif_funcs[] =
{
	{"compress", 3, compress},
	{"uncompress", 3, uncompress}
};

ERL_NIF_INIT(rle_nif, nif_funcs, load_cb, NULL, NULL, unload_cb)
