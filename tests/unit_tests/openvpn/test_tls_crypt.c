/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "tls_crypt.c"

#include "mock_msg.h"

/* Define this function here as dummy since including the ssl_*.c files
 * leads to having to include even more unrelated code */
bool
key_state_export_keying_material(struct tls_session *session,
                                 const char *label, size_t label_size,
                                 void *ekm, size_t ekm_size)
{
    memset(ekm, 0xba, ekm_size);
    return true;
}


#define TESTBUF_SIZE            128

/* Defines for use in the tests and the mock parse_line() */
#define PATH1       "/s p a c e"
#define PATH2       "/foo bar/baz"
#define PARAM1      "param1"
#define PARAM2      "param two"

static const char *test_server_key = \
    "-----BEGIN OpenVPN tls-crypt-v2 server key-----\n"
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
    "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8=\n"
    "-----END OpenVPN tls-crypt-v2 server key-----\n";

static const char *test_client_key = \
    "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
    "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n"
    "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/\n"
    "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v\n"
    "8PHy8/T19vf4+fr7/P3+/xd9pcB0qUYZsWvkrLcfGmzPJPM8a7r0mEWdXwbDadSV\n"
    "LHg5bv2TwlmPR3HgaMr8o9LTh9hxUTkrH3S0PfKRNwcso86ua/dBFTyXsM9tg4aw\n"
    "3dS6ogH9AkaT+kRRDgNcKWkQCbwmJK2JlfkXHBwbAtmn78AkNuho6QCFqCdqGab3\n"
    "zh2vheFqGMPdGpukbFrT3rcO3VLxUeG+RdzXiMTCpJSovFBP1lDkYwYJPnz6daEh\n"
    "j0TzJ3BVru9W3CpotdNt7u09knxAfpCxjtrP3semsDew/gTBtcfQ/OoTFyFHnN5k\n"
    "RZ+q17SC4nba3Pp8/Fs0+hSbv2tJozoD8SElFq7SIWJsciTYh8q8f5yQxjdt4Wxu\n"
    "/Z5wtPCAZ0tOzj4ItTI77fBOYRTfEayzHgEr\n"
    "-----END OpenVPN tls-crypt-v2 client key-----\n";


/* Has custom metadata of AABBCCDD (base64) */
static const char *test_client_key_metadata = \
    "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
    "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n"
    "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/\n"
    "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v\n"
    "8PHy8/T19vf4+fr7/P3+/2ntp1WCqhcLjJQY/igkjNt3Yb6i0neqFkfrOp2UCDcz\n"
    "6RSJtPLZbvOOKUHk2qwxPYUsFCnz/IWV6/ZiLRrabzUpS8oSN1HS6P7qqAdrHKgf\n"
    "hVTHasdSf2UdMTPC7HBgnP9Ll0FhKN0h7vSzbbt7QM7wH9mr1ecc/Mt0SYW2lpwA\n"
    "aJObYGTyk6hTgWm0g/MLrworLrezTqUHBZzVsu+LDyqLWK1lzJNd66MuNOsGA4YF\n"
    "fbCsDh8n3H+Cw1k5YNBZDYYJOtVUgBWXheO6vgoOmqDdI0dAQ3hVo9DE+SkCFjgf\n"
    "l4FY2yLEh9ZVZZrl1eD1Owh/X178CkHrBJYl9LNQSyQEKlDGWwBLQ/pY3qtjctr3\n"
    "pV62MPQdBo+1lcsjDCJVQA6XUyltas4BKQ==\n"
    "-----END OpenVPN tls-crypt-v2 client key-----\n";

int
__wrap_parse_line(const char *line, char **p, const int n, const char *file,
                  const int line_num, int msglevel, struct gc_arena *gc)
{
    p[0] = PATH1 PATH2;
    p[1] = PARAM1;
    p[2] = PARAM2;
    return 3;
}

bool
__wrap_buffer_write_file(const char *filename, const struct buffer *buf)
{
    const char *pem = BSTR(buf);
    check_expected(filename);
    check_expected(pem);

    return mock_type(bool);
}

struct buffer
__wrap_buffer_read_from_file(const char *filename, struct gc_arena *gc)
{
    check_expected(filename);

    const char *pem_str = mock_ptr_type(const char *);
    struct buffer ret = alloc_buf_gc(strlen(pem_str) + 1, gc);
    buf_write(&ret, pem_str, strlen(pem_str) + 1);

    return ret;
}


/** Predictable random for tests */
int
__wrap_rand_bytes(uint8_t *output, int len)
{
    for (int i = 0; i < len; i++)
    {
        output[i] = i;
    }
    return true;
}

struct test_tls_crypt_context {
    struct crypto_options co;
    struct key_type kt;
    struct buffer source;
    struct buffer ciphertext;
    struct buffer unwrapped;
};


static int
test_tls_crypt_setup(void **state)
{
    struct test_tls_crypt_context *ctx = calloc(1, sizeof(*ctx));
    *state = ctx;

    struct key key = { 0 };

    ctx->kt = tls_crypt_kt();
    if (!ctx->kt.cipher || !ctx->kt.digest)
    {
        return 0;
    }
    init_key_ctx(&ctx->co.key_ctx_bi.encrypt, &key, &ctx->kt, true, "TEST");
    init_key_ctx(&ctx->co.key_ctx_bi.decrypt, &key, &ctx->kt, false, "TEST");

    packet_id_init(&ctx->co.packet_id, 0, 0, "test", 0);

    ctx->source = alloc_buf(TESTBUF_SIZE);
    ctx->ciphertext = alloc_buf(TESTBUF_SIZE);
    ctx->unwrapped = alloc_buf(TESTBUF_SIZE);

    /* Write test plaintext */
    const char *plaintext = "1234567890";
    buf_write(&ctx->source, plaintext, strlen(plaintext));

    /* Write test ciphertext */
    const char *ciphertext = "012345678";
    buf_write(&ctx->ciphertext, ciphertext, strlen(ciphertext));

    return 0;
}

static int
test_tls_crypt_teardown(void **state)
{
    struct test_tls_crypt_context *ctx =
        (struct test_tls_crypt_context *)*state;

    free_buf(&ctx->source);
    free_buf(&ctx->ciphertext);
    free_buf(&ctx->unwrapped);

    free_key_ctx_bi(&ctx->co.key_ctx_bi);

    free(ctx);

    return 0;
}

static void
skip_if_tls_crypt_not_supported(struct test_tls_crypt_context *ctx)
{
    if (!ctx->kt.cipher || !ctx->kt.digest)
    {
        skip();
    }
}

/**
 * Check that short messages are successfully wrapped-and-unwrapped.
 */
static void
tls_crypt_loopback(void **state)
{
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
    assert_int_equal(BLEN(&ctx->source), BLEN(&ctx->unwrapped));
    assert_memory_equal(BPTR(&ctx->source), BPTR(&ctx->unwrapped),
                        BLEN(&ctx->source));
}


/**
 * Test generating dynamic tls-crypt key
 */
static void
test_tls_crypt_secure_reneg_key(void **state)
{
    struct test_tls_crypt_context *ctx =
        (struct test_tls_crypt_context *)*state;

    struct gc_arena gc = gc_new();

    struct tls_multi multi = { 0 };
    struct tls_session session = { 0 };

    struct tls_options tls_opt = { 0 };
    tls_opt.replay_window = 32;
    tls_opt.replay_time = 60;
    tls_opt.frame.buf.payload_size = 512;
    session.opt = &tls_opt;

    tls_session_generate_dynamic_tls_crypt_key(&multi, &session);

    struct tls_wrap_ctx *rctx = &session.tls_wrap_reneg;

    tls_crypt_wrap(&ctx->source, &rctx->work, &rctx->opt);
    assert_int_equal(buf_len(&ctx->source) + 40, buf_len(&rctx->work));

    uint8_t expected_ciphertext[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xe3, 0x19, 0x27, 0x7f, 0x1c, 0x8d, 0x6e, 0x6a,
        0x77, 0x96, 0xa8, 0x55, 0x33, 0x7b, 0x9c, 0xfb, 0x56, 0xe1, 0xf1, 0x3a, 0x87, 0x0e, 0x66, 0x47,
        0xdf, 0xa1, 0x95, 0xc9, 0x2c, 0x17, 0xa0, 0x15, 0xba, 0x49, 0x67, 0xa1, 0x1d, 0x55, 0xea, 0x1a,
        0x06, 0xa7
    };
    assert_memory_equal(BPTR(&rctx->work), expected_ciphertext, buf_len(&rctx->work));
    tls_wrap_free(&session.tls_wrap_reneg);

    /* Use previous tls-crypt key as 0x00, with xor we should have the same key
     * and expect the same result */
    session.tls_wrap.mode = TLS_WRAP_CRYPT;
    memset(&session.tls_wrap.original_wrap_keydata.keys, 0x00, sizeof(session.tls_wrap.original_wrap_keydata.keys));
    session.tls_wrap.original_wrap_keydata.n = 2;

    tls_session_generate_dynamic_tls_crypt_key(&multi, &session);
    tls_crypt_wrap(&ctx->source, &rctx->work, &rctx->opt);
    assert_int_equal(buf_len(&ctx->source) + 40, buf_len(&rctx->work));

    assert_memory_equal(BPTR(&rctx->work), expected_ciphertext, buf_len(&rctx->work));
    tls_wrap_free(&session.tls_wrap_reneg);

    /* XOR should not force a different key */
    memset(&session.tls_wrap.original_wrap_keydata.keys, 0x42, sizeof(session.tls_wrap.original_wrap_keydata.keys));
    tls_session_generate_dynamic_tls_crypt_key(&multi, &session);

    tls_crypt_wrap(&ctx->source, &rctx->work, &rctx->opt);
    assert_int_equal(buf_len(&ctx->source) + 40, buf_len(&rctx->work));

    /* packet id at the start should be equal */
    assert_memory_equal(BPTR(&rctx->work), expected_ciphertext, 8);

    /* Skip packet id */
    buf_advance(&rctx->work, 8);
    assert_memory_not_equal(BPTR(&rctx->work), expected_ciphertext, buf_len(&rctx->work));
    tls_wrap_free(&session.tls_wrap_reneg);


    gc_free(&gc);
}

/**
 * Check that zero-byte messages are successfully wrapped-and-unwrapped.
 */
static void
tls_crypt_loopback_zero_len(void **state)
{
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    buf_clear(&ctx->source);

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
    assert_int_equal(BLEN(&ctx->source), BLEN(&ctx->unwrapped));
    assert_memory_equal(BPTR(&ctx->source), BPTR(&ctx->unwrapped),
                        BLEN(&ctx->source));
}

/**
 * Check that max-length messages are successfully wrapped-and-unwrapped.
 */
static void
tls_crypt_loopback_max_len(void **state)
{
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    buf_clear(&ctx->source);
    assert_non_null(buf_write_alloc(&ctx->source,
                                    TESTBUF_SIZE - BLEN(&ctx->ciphertext) - tls_crypt_buf_overhead()));

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
    assert_int_equal(BLEN(&ctx->source), BLEN(&ctx->unwrapped));
    assert_memory_equal(BPTR(&ctx->source), BPTR(&ctx->unwrapped),
                        BLEN(&ctx->source));
}

/**
 * Check that too-long messages are gracefully rejected.
 */
static void
tls_crypt_fail_msg_too_long(void **state)
{
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    buf_clear(&ctx->source);
    assert_non_null(buf_write_alloc(&ctx->source,
                                    TESTBUF_SIZE - BLEN(&ctx->ciphertext) - tls_crypt_buf_overhead() + 1));
    assert_false(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
}

/**
 * Check that packets that were wrapped (or unwrapped) with a different key
 * are not accepted.
 */
static void
tls_crypt_fail_invalid_key(void **state)
{
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    /* Change decrypt key */
    struct key key = { { 1 } };
    free_key_ctx(&ctx->co.key_ctx_bi.decrypt);
    init_key_ctx(&ctx->co.key_ctx_bi.decrypt, &key, &ctx->kt, false, "TEST");

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    assert_false(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

/**
 * Check that replayed packets are not accepted.
 */
static void
tls_crypt_fail_replay(void **state)
{
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    struct buffer tmp = ctx->ciphertext;
    assert_true(tls_crypt_unwrap(&tmp, &ctx->unwrapped, &ctx->co));
    buf_clear(&ctx->unwrapped);
    assert_false(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

/**
 * Check that packet replays are accepted when CO_IGNORE_PACKET_ID is set. This
 * is used for the first control channel packet that arrives, because we don't
 * know the packet ID yet.
 */
static void
tls_crypt_ignore_replay(void **state)
{
    struct test_tls_crypt_context *ctx = (struct test_tls_crypt_context *) *state;

    skip_if_tls_crypt_not_supported(ctx);

    ctx->co.flags |= CO_IGNORE_PACKET_ID;

    assert_true(tls_crypt_wrap(&ctx->source, &ctx->ciphertext, &ctx->co));
    assert_true(BLEN(&ctx->source) < BLEN(&ctx->ciphertext));
    struct buffer tmp = ctx->ciphertext;
    assert_true(tls_crypt_unwrap(&tmp, &ctx->unwrapped, &ctx->co));
    buf_clear(&ctx->unwrapped);
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

struct test_tls_crypt_v2_context {
    struct gc_arena gc;
    struct key2 server_key2;
    struct key_ctx_bi server_keys;
    struct key2 client_key2;
    struct key_ctx_bi client_key;
    struct buffer metadata;
    struct buffer unwrapped_metadata;
    struct buffer wkc;
};

static int
test_tls_crypt_v2_setup(void **state)
{
    struct test_tls_crypt_v2_context *ctx = calloc(1, sizeof(*ctx));
    *state = ctx;

    ctx->gc = gc_new();

    /* Slightly longer buffers to be able to test too-long data */
    ctx->metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN+16, &ctx->gc);
    ctx->unwrapped_metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN+16,
                                           &ctx->gc);
    ctx->wkc = alloc_buf_gc(TLS_CRYPT_V2_MAX_WKC_LEN+16, &ctx->gc);

    /* Generate server key */
    rand_bytes((void *)ctx->server_key2.keys, sizeof(ctx->server_key2.keys));
    ctx->server_key2.n = 2;
    struct key_type kt = tls_crypt_kt();
    init_key_ctx_bi(&ctx->server_keys, &ctx->server_key2,
                    KEY_DIRECTION_BIDIRECTIONAL, &kt,
                    "tls-crypt-v2 server key");

    /* Generate client key */
    rand_bytes((void *)ctx->client_key2.keys, sizeof(ctx->client_key2.keys));
    ctx->client_key2.n = 2;

    return 0;
}

static int
test_tls_crypt_v2_teardown(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    free_key_ctx_bi(&ctx->server_keys);
    free_key_ctx_bi(&ctx->client_key);

    gc_free(&ctx->gc);

    free(ctx);

    return 0;
}

/**
 * Check wrapping and unwrapping a tls-crypt-v2 client key without metadata.
 */
static void
tls_crypt_v2_wrap_unwrap_no_metadata(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    struct buffer wrapped_client_key = alloc_buf_gc(TLS_CRYPT_V2_MAX_WKC_LEN,
                                                    &ctx->gc);
    assert_true(tls_crypt_v2_wrap_client_key(&wrapped_client_key,
                                             &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    struct buffer unwrap_metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN,
                                                 &ctx->gc);
    struct key2 unwrapped_client_key2 = { 0 };
    assert_true(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                               &unwrap_metadata,
                                               wrapped_client_key,
                                               &ctx->server_keys.decrypt));

    assert_true(0 == memcmp(ctx->client_key2.keys, unwrapped_client_key2.keys,
                            sizeof(ctx->client_key2.keys)));
}

/**
 * Check wrapping and unwrapping a tls-crypt-v2 client key with maximum length
 * metadata.
 */
static void
tls_crypt_v2_wrap_unwrap_max_metadata(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    uint8_t *metadata =
        buf_write_alloc(&ctx->metadata, TLS_CRYPT_V2_MAX_METADATA_LEN);
    assert_true(rand_bytes(metadata, TLS_CRYPT_V2_MAX_METADATA_LEN));
    assert_true(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    struct buffer unwrap_metadata = alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN,
                                                 &ctx->gc);
    struct key2 unwrapped_client_key2 = { 0 };
    assert_true(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                               &unwrap_metadata, ctx->wkc,
                                               &ctx->server_keys.decrypt));

    assert_true(0 == memcmp(ctx->client_key2.keys, unwrapped_client_key2.keys,
                            sizeof(ctx->client_key2.keys)));
    assert_true(buf_equal(&ctx->metadata, &unwrap_metadata));

    struct tls_wrap_ctx wrap_ctx = {
        .mode = TLS_WRAP_CRYPT,
        .tls_crypt_v2_server_key = ctx->server_keys.encrypt,
    };
    assert_true(tls_crypt_v2_extract_client_key(&ctx->wkc, &wrap_ctx, NULL));
    tls_wrap_free(&wrap_ctx);
}

/**
 * Check that wrapping a tls-crypt-v2 client key with too long metadata fails
 * as expected.
 */
static void
tls_crypt_v2_wrap_too_long_metadata(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    assert_true(buf_inc_len(&ctx->metadata, TLS_CRYPT_V2_MAX_METADATA_LEN+1));
    assert_false(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                              &ctx->metadata,
                                              &ctx->server_keys.encrypt,
                                              &ctx->gc));
}

/**
 * Check that unwrapping a tls-crypt-v2 client key with the wrong server key
 * fails as expected.
 */
static void
tls_crypt_v2_wrap_unwrap_wrong_key(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    assert_true(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    /* Change server key */
    struct key_type kt = tls_crypt_kt();
    free_key_ctx_bi(&ctx->server_keys);
    memset(&ctx->server_key2.keys, 0, sizeof(ctx->server_key2.keys));
    init_key_ctx_bi(&ctx->server_keys, &ctx->server_key2,
                    KEY_DIRECTION_BIDIRECTIONAL, &kt,
                    "wrong tls-crypt-v2 server key");


    struct key2 unwrapped_client_key2 = { 0 };
    assert_false(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                                &ctx->unwrapped_metadata,
                                                ctx->wkc,
                                                &ctx->server_keys.decrypt));

    const struct key2 zero = { 0 };
    assert_true(0 == memcmp(&unwrapped_client_key2, &zero, sizeof(zero)));
    assert_true(0 == BLEN(&ctx->unwrapped_metadata));
}

/**
 * Check that unwrapping a tls-crypt-v2 client key to a too small metadata
 * buffer fails as expected.
 */
static void
tls_crypt_v2_wrap_unwrap_dst_too_small(void **state)
{
    struct test_tls_crypt_v2_context *ctx =
        (struct test_tls_crypt_v2_context *) *state;

    uint8_t *metadata =
        buf_write_alloc(&ctx->metadata, TLS_CRYPT_V2_MAX_METADATA_LEN);
    assert_true(rand_bytes(metadata, TLS_CRYPT_V2_MAX_METADATA_LEN));
    assert_true(tls_crypt_v2_wrap_client_key(&ctx->wkc, &ctx->client_key2,
                                             &ctx->metadata,
                                             &ctx->server_keys.encrypt,
                                             &ctx->gc));

    struct key2 unwrapped_client_key2 = { 0 };
    struct buffer unwrapped_metadata =
        alloc_buf_gc(TLS_CRYPT_V2_MAX_METADATA_LEN-1, &ctx->gc);
    assert_false(tls_crypt_v2_unwrap_client_key(&unwrapped_client_key2,
                                                &unwrapped_metadata, ctx->wkc,
                                                &ctx->server_keys.decrypt));

    const struct key2 zero = { 0 };
    assert_true(0 == memcmp(&unwrapped_client_key2, &zero, sizeof(zero)));
    assert_true(0 == BLEN(&ctx->unwrapped_metadata));
}

static void
test_tls_crypt_v2_write_server_key_file(void **state)
{
    const char *filename = "testfilename.key";

    expect_string(__wrap_buffer_write_file, filename, filename);
    expect_memory(__wrap_buffer_write_file, pem, test_server_key,
                  strlen(test_server_key));
    will_return(__wrap_buffer_write_file, true);

    tls_crypt_v2_write_server_key_file(filename);
}

static void
test_tls_crypt_v2_write_client_key_file(void **state)
{
    const char *filename = "testfilename.key";

    /* Test writing the client key */
    expect_string(__wrap_buffer_write_file, filename, filename);
    expect_memory(__wrap_buffer_write_file, pem, test_client_key,
                  strlen(test_client_key));
    will_return(__wrap_buffer_write_file, true);

    /* Key generation re-reads the created file as a sanity check */
    expect_string(__wrap_buffer_read_from_file, filename, filename);
    will_return(__wrap_buffer_read_from_file, test_client_key);

    tls_crypt_v2_write_client_key_file(filename, NULL, test_server_key, true);
}

static void
test_tls_crypt_v2_write_client_key_file_metadata(void **state)
{
    const char *filename = "testfilename.key";
    const char *b64metadata = "AABBCCDD";

    /* Test writing the client key */
    expect_string(__wrap_buffer_write_file, filename, filename);
    expect_memory(__wrap_buffer_write_file, pem, test_client_key_metadata,
                  strlen(test_client_key_metadata));
    will_return(__wrap_buffer_write_file, true);

    /* Key generation re-reads the created file as a sanity check */
    expect_string(__wrap_buffer_read_from_file, filename, filename);
    will_return(__wrap_buffer_read_from_file, test_client_key_metadata);

    tls_crypt_v2_write_client_key_file(filename, b64metadata, test_server_key,
                                       true);
}

static void
test_tls_crypt_reynir(void **state)
{
    struct test_tls_crypt_context *ctx = calloc(1, sizeof (*ctx));

    char key[] = "\xde\x17\x88\xa8\xfa\x0c\xdb\x61\xf4\x0d\xa8\xbd\x34\xca\xb6\xf8\xa2\x25\x62\x77\x4e\xe7\xaf\xe6\x56\x30\x7f\xcd\x0a\xb2\x07\xf0\xf5\xa8\xd8\x9a\xb4\x14\x3d\xd9\x79\x38\x03\x55\xa6\xcf\xf4\x9b\xd6\xca\x49\xf9\x3a\x74\x03\x43\xd8\x06\xc0\x2a\x3c\x0d\x73\x72\x1c\xfc\x83\xa9\xbe\x17\x29\x53\x4f\x52\xcc\x44\x5c\x65\x9a\xe8\x4d\x79\x5f\xa1\x4e\xe9\x0b\x3d\x19\x8f\x84\xf5\xcd\x47\x0a\x47\x72\x88\x80\x73\x9c\xb9\x01\xfd\xd3\x64\xb1\x09\x0b\x64\x66\x68\x2e\xa7\x07\x27\xdc\xef\x79\x1f\xc5\x78\xf0\xfb\xe5\x1d\xd4\xe9\xcd\x8f\xe4\x8c\x61\xe6\x30\x9a\x62\xde\x50\x44\xd4\x45\x27\x06\xa9\x13\x73\x1d\xc4\xa4\x3c\x07\x68\xf7\x0e\xfc\x42\x6d\xa7\x83\x99\xa3\x56\x15\x5b\xf6\x42\xbf\xa7\x62\x80\xe2\xdc\x11\x10\x00\x4c\x57\x46\x5c\xcb\xfb\xf5\x66\x70\xdd\x38\x29\xa7\xb7\xbb\xaa\xb6\x2d\x11\x46\xf1\x12\xa6\x0e\x4e\x05\xcf\xb5\xe3\x57\x68\x2f\x7a\x54\x3a\x67\x34\xfe\x41\x34\x96\x1c\x2c\x6c\x6c\x42\x5a\xc5\x54\x6d\x8b\xbb\x03\xaf\xa2\x8b\x99\x7f\xd5\x22\xff\x80\xc8\x9c\x2a\x16\x4c\xb8\xd7\xf7\xdb\x7d\x24\xd6\x30\x4d\x56\xbb\x87\x7d\x22\x1f\xbd\x3f\xe8\x1e\x65\x36\xcf\xec\x1e\xaa\x31\x05\xc3\x75\xba\x7b\x25\x1d\x0d\x23\x04\x57\xb5\xc8\x55\xb2\xc5\xa4\x26\xe5\xe5\x4b\x0b\xe6\xef\x49\x80\xc6\x02\xfe\xb5\xcb\x53\xce\x83\xd0\x30\xc4\xdc\x08\x9c\xb5\x71\x23\x14\xd4\xf0\xd1\xd6\xd4\x7b\x70\xc6\x1b\xcc\xa2\xb4\xa0\x65\x0d\x6e\xba\xf9\x95\x22\x6a\x7c\x99\xa5\xed\xb1\x4e\x9c\xb6\xa2\x1e\x1a\x48\x30\xc8\x04\x40\x06\xf9\xf8\xd0\x17\x13\x57\xaf\x30\xe3\x25\xff\x2a\x0c\xb8\x7d\xcd\xeb\x0a\x65\x9a\x47\x9b\xaa\x06\x5a\xcc\x3a\x77\x99\x77\x39\xfa\x21\x98\x54\x91\x74\xde\xfa\x07\xff\x6a\xb8\x30\xec\x44\xdb\x05\xdf\x37\x07\x1a\xe4\x4b\x91\x5c\xe5\xfb\x9e\x3b\x8e\xb4\xb3\x6c\xc5\xa8\x2c\xfc\x3c\x6a\x59\xf2\x97\x7a\xca\x1f\x48\xfb\x4d\x16\xb6\x1d\x90\x9b\x3c\x9e\x7d\x5e\x5b\xa7\xaa\xfd\xb0\xaa\xe2\xb4\xc1\x13\x6c\xe8\x4f\x71\xd3\x88\x34\xb9\x52\x4e\xfd\x9d\xca\x62\x45\x44\x75\x93\x85\xb2\xf7\xd0\xf0\xd7\x61\x8a\x91\xd9\x41\xb1\x6a\xf8\x9a\xdf\x51\x93\x1a\x47\x2a\x47\x04\x0b\xe6\x75\x38\xfe\xed\xd7\x5a\x66\x77\x32\x3f\x35\x24\x58\x7b\xfe\x81\x2a\x2e\xd1\x2d\x2b\x09\xbe\x2d\x09\x46\xb8\xf1\xf2\xaf\x9d\xc0\x7e\x84\xc4\x76\xdc\xd4\x41\x00\x6f\x00\x4a\x9d\xc4\xb9\x9c\x9a\x3a\x46\xdc\xa7\x36\x7c\x9e\xba\x4c\x51\xea\x71\x89\x60\x51\x93\xde\x01\x2f";
    struct key server_key, client_key;

    mock_set_debug_level(9);

    memcpy(&server_key, key, sizeof(struct key));
    memcpy(&client_key, key + sizeof(struct key), sizeof(struct key));

    ctx->kt = tls_crypt_kt();

    init_key_ctx(&ctx->co.key_ctx_bi.encrypt, &client_key, &ctx->kt, true, "TEST_client");
    init_key_ctx(&ctx->co.key_ctx_bi.decrypt, &server_key, &ctx->kt, false, "TEST_server");

    /* FIXME should use correct packet id */
    packet_id_init(&ctx->co.packet_id, 0, 0, "test", 0);

    ctx->source = alloc_buf(1536);
    ctx->ciphertext = alloc_buf(1536);
    ctx->unwrapped = alloc_buf(1536);

    uint8_t pkt[] = {
        0x04, 0xb6, 0x20, 0xf1, 0x0b, 0x2c, 0x55, 0x9a,  0x18, 0x56, 0x26, 0x0f, 0x00, 0x00, 0x04, 0x65,
        0x4a, 0x4e, 0x42, 0x66, 0xde, 0x17, 0x26, 0x0b,  0x86, 0x88, 0xcc, 0xcc, 0xc0, 0xa0, 0x9d, 0x94,
        0x36, 0xbf, 0x00, 0x4a, 0x3c, 0x8c, 0x20, 0xac,  0x01, 0x91, 0x92, 0x94, 0x3f, 0x50, 0xfc, 0x93,
        0x6a, 0x2b, 0x63, 0x40, 0x0d, 0x70, 0xaf, 0x72,  0x58, 0x43, 0x64, 0x15, 0xe2, 0x06, 0x51, 0x41,
        0x74, 0xfd, 0xfd, 0x90, 0x32, 0x89, 0x8a, 0x95,  0x67, 0x4c, 0x47, 0x73, 0xcb, 0x9a, 0x63, 0x78,
        0xbc, 0x70, 0xfc, 0x71, 0xca, 0x02, 0xd6, 0x18,  0x2c, 0x0d, 0xcf, 0xd1, 0x63, 0xde, 0x14, 0xaf,
        0x4a, 0x1d, 0xee, 0xc6, 0xcb, 0x28, 0x79, 0x2c,  0x2a, 0x93, 0x97, 0x5f, 0x0b, 0xe7, 0xc3, 0xf4,
        0xeb, 0x57, 0xc8, 0xac, 0x08, 0x51, 0x23, 0x9e,  0x0a, 0x4f, 0x5e, 0x89, 0xa0, 0x11, 0x00, 0x67,
        0xc9, 0xf8, 0xb4, 0x52, 0x39, 0x98, 0x31, 0x1c,  0x18, 0xd3, 0xd3, 0xc0, 0x76, 0x00, 0x67, 0x15,
        0x3e, 0x6b, 0x21, 0x5f, 0x56, 0x9d, 0x92, 0xc4,  0xd5, 0xbf, 0xa4, 0x37, 0x2a, 0x0b, 0x00, 0xe4,
        0x3b, 0xfc, 0xdf, 0x4b, 0x82, 0x2d, 0xe1, 0xac,  0xf1, 0xa1, 0x56, 0xdc, 0x95, 0x28, 0x41, 0xb5,
        0xad, 0x10, 0xc7, 0x68, 0x96, 0x60, 0xd5, 0xde,  0x43, 0x69, 0x31, 0xde, 0xb5, 0x4f, 0x7d, 0xac,
        0x59, 0x7f, 0x27, 0xc8, 0xd2, 0x9d, 0xd5, 0x3c,  0x71, 0xa5, 0x7f, 0x8b, 0xa2, 0x03, 0x78, 0x06,
        0x33, 0xd1, 0xfb, 0xb5, 0xff, 0x70, 0x52, 0xc5,  0x8c, 0x9e, 0x05, 0x37, 0x6e, 0x11, 0x08, 0x98,
        0x2b, 0x31, 0x7f, 0xc8, 0x34, 0x38, 0xbe, 0xf3,  0xa5, 0x02, 0x80, 0x76, 0xda, 0xc4, 0xfb, 0x01,
        0x00, 0xe8, 0x20, 0xf1, 0x0b, 0x2c, 0x55, 0x9a,  0x18, 0x56, 0x26, 0x0f, 0x00, 0x00, 0x06, 0x65,
        0x4a, 0x4e, 0x42, 0x1e, 0x75, 0x0d, 0x8c, 0xbf,  0x15, 0xcc, 0x0f, 0x14, 0x5b, 0x1c, 0xa8, 0x90,
        0xf7, 0x36, 0x6d, 0xd1, 0x9e, 0x13, 0xef, 0x6e,  0x9b, 0xdc, 0xf0, 0x0b, 0xa4, 0xb4, 0x08, 0xc9,
        0x5b, 0x8c, 0x29, 0xe9, 0x69, 0x71, 0xa6, 0x8d,  0xd7, 0x24, 0x88, 0x8b, 0x16, 0x79, 0x94, 0x71,
        0x20, 0x50, 0x6b, 0xeb, 0x9d, 0x9e, 0xdd, 0xd4,  0x44, 0x5e, 0xa1, 0x1a, 0x87, 0x93, 0x04, 0x9a,
        0x0e, 0x0f, 0x97, 0x85, 0xd2, 0x0c, 0x8b, 0x2e,  0x44, 0xd7, 0x56, 0x71, 0xdd, 0xda, 0xf6, 0xa2,
        0xea, 0xd6, 0xbe, 0x65, 0x2d, 0x6e, 0xd1, 0xb3,  0xda, 0x87, 0x7d, 0x24, 0x7f, 0x41, 0x8b, 0xe3,
        0xac, 0xd5, 0xf0, 0x20, 0x8a, 0xe1, 0x0f, 0x1a,  0x9c, 0xf3, 0x72, 0xd5, 0x8e, 0x8b, 0x50, 0x5c,
        0x99, 0x2b, 0x84, 0x15, 0x07, 0x2a, 0x79, 0xe4,  0x64, 0x33, 0xe4, 0x7b, 0x03, 0x4b, 0x45, 0x4f,
        0x6a, 0x8b, 0x6f, 0x7f, 0xeb, 0x82, 0xc3, 0x19,  0xb6, 0xf3, 0xac, 0x61, 0x69, 0xbc, 0x0f, 0x8d,
        0x60, 0x07, 0xe1, 0x1e, 0xdd, 0x76, 0x38, 0x79,  0x15, 0x4c, 0xc3, 0xdc, 0x3e, 0x72, 0x3e, 0xb6,
        0x8b, 0x7e, 0xbb, 0x4b, 0x79, 0xda, 0x0e, 0x40,  0xac, 0x38, 0xce, 0xba, 0x6c, 0xd9, 0xc8, 0x9a,
        0xa3, 0xc4, 0x2f, 0x31, 0x19, 0xf8, 0xe5, 0x88,  0x18, 0x4d, 0xe3, 0x03, 0x7b, 0x41, 0x7a, 0xbe,
        0xb3, 0x7d, 0xcb, 0x39, 0xb9, 0xdb, 0xc0, 0xd2,  0x5c, 0x6f, 0x2d, 0x00, 0xd1, 0xef, 0xf8, 0x48,
        0x91, 0x00, 0xfc, 0x84, 0x7e, 0xfb, 0x67, 0xde,  0x4d, 0xdb, 0x01, 0x1d, 0x20, 0xf1, 0x0b, 0x2c,
        0x55, 0x9a, 0x18, 0x56, 0x26, 0x0f, 0x00, 0x00,  0x07, 0x65, 0x4a, 0x4e, 0x42, 0xce, 0xd5, 0x84,
        0x6f, 0xcb, 0xed, 0xa0, 0x19, 0xad, 0xf7, 0x09,  0x74, 0xbe, 0x36, 0x62, 0x21, 0x85, 0x7d, 0x8d,
        0x6a, 0x0b, 0x6b, 0x55, 0x41, 0xb3, 0x48, 0x3e,  0x9b, 0x14, 0xe3, 0x3f, 0x8e, 0xff, 0x53, 0xc1,
        0x8e, 0x4e, 0x4d, 0x83, 0x2a, 0x3a, 0x29, 0x34,  0x96, 0x61, 0x1e, 0x0e, 0x29, 0xd0, 0xb3, 0x7d,
        0x47, 0xea, 0x2d, 0x8f, 0xb6, 0xff, 0x8f, 0x75,  0x5c, 0xd2, 0xc8, 0x8b, 0xdc, 0xf5, 0xfa, 0xff,
        0xa9, 0xf5, 0x77, 0xf5, 0x82, 0xfa, 0xdf, 0xaa,  0x88, 0x23, 0x72, 0x2c, 0x10, 0x89, 0x9d, 0xfc,
        0xda, 0x79, 0xa3, 0x9c, 0x94, 0xf4, 0xd2, 0xfa,  0x12, 0x40, 0xef, 0x71, 0xd2, 0x99, 0x86, 0xff,
        0x40, 0x57, 0x09, 0x53, 0x72, 0xc1, 0x19, 0xab,  0x07, 0xe5, 0xd7, 0x68, 0x44, 0xd8, 0xee, 0x23,
        0xef, 0x6f, 0x24, 0x05, 0xb0, 0xfd, 0xc2, 0x72,  0x44, 0x29, 0xcb, 0xaf, 0x6f, 0x2e, 0x5e, 0x5f,
        0x6a, 0x6d, 0xf6, 0xb7, 0x60, 0x49, 0xb9, 0xb0,  0x5d, 0x02, 0x41, 0x21, 0x5a, 0xd7, 0x4a, 0x16,
        0xcc, 0xcd, 0xa6, 0x01, 0x6e, 0xc0, 0x9d, 0x71,  0xf9, 0x99, 0x25, 0x8c, 0xa4, 0xec, 0x8e, 0xe5,
        0xd9, 0xa3, 0x3f, 0xa3, 0xb2, 0xd5, 0x8c, 0xd0,  0xf4, 0x30, 0x1a, 0x42, 0xbc, 0x16, 0xa3, 0x84,
        0x56, 0xf7, 0x6d, 0xee, 0x40, 0xe0, 0xa0, 0xa0,  0xf0, 0x57, 0x11, 0x55, 0x9f, 0x1f, 0x32, 0xe4,
        0xb7, 0x8e, 0x6a, 0x51, 0xb1, 0xed, 0xd1, 0xf6,  0x6c, 0xae, 0x7d, 0xc8, 0x85, 0x73, 0xed, 0xc3,
        0x51, 0x03, 0x49, 0x2c, 0x32, 0xbd, 0xf2, 0xc8,  0xd0, 0x7a, 0xec, 0x5e, 0x4e, 0x50, 0xc5, 0xec,
        0xf9, 0xab, 0xfc, 0x04, 0xa5, 0xd3, 0x40, 0xb9,  0x9a, 0x46, 0xe8, 0x6e, 0x3f, 0x81, 0xb5, 0x3c,
        0x70, 0x9b, 0x85, 0x5d, 0x63, 0xf2, 0x07, 0xa8,  0x48, 0xfd, 0x50, 0xcf, 0x1b, 0xf4, 0xab, 0xea,
        0x11, 0x68, 0xbc, 0xa3, 0x76, 0xf8, 0x97, 0x3d,  0xe0, 0x00, 0xec, 0x20, 0xf1, 0x0b, 0x2c, 0x55,
        0x9a, 0x18, 0x56, 0x26, 0x0f, 0x00, 0x00, 0x08,  0x65, 0x4a, 0x4e, 0x42, 0xc7, 0x07, 0x81, 0x7e,
        0x70, 0xc6, 0xdc, 0xfc, 0xe2, 0x2a, 0xf4, 0xf0,  0x04, 0x3e, 0x92, 0x92, 0xf5, 0xb6, 0x9a, 0xd8,
        0x0e, 0x08, 0x94, 0xc7, 0x62, 0xe1, 0x91, 0x89,  0x36, 0xba, 0xc5, 0xf2, 0xc8, 0x5e, 0x3a, 0x76,
        0x4a, 0xce, 0x8a, 0x18, 0x55, 0x46, 0xc3, 0x1f,  0x9f, 0x23, 0x48, 0x53, 0xb0, 0xb7, 0x70, 0x53,
        0x9c, 0x06, 0x99, 0xd2, 0x27, 0x7d, 0x17, 0x86,  0x82, 0xb7, 0x72, 0x74, 0xfd, 0x8e, 0x8f, 0xa5,
        0x4b, 0x52, 0x01, 0x7b, 0x5a, 0x2c, 0x02, 0x02,  0x95, 0x9c, 0xa0, 0x81, 0x17, 0x2c, 0x7d, 0xaf,
        0x16, 0x7a, 0x47, 0xa1, 0x5d, 0xbf, 0x8f, 0x0f,  0xc5, 0x6b, 0x9f, 0x93, 0xf9, 0x8c, 0xf7, 0xe8,
        0xa0, 0xa9, 0xbe, 0x84, 0xde, 0xfd, 0x8e, 0xa6,  0x90, 0xe7, 0xa6, 0x30, 0xee, 0x5c, 0xb9, 0x3b,
        0xd9, 0xa5, 0xa7, 0xba, 0x3b, 0x3b, 0x6a, 0xa6,  0xf7, 0xcb, 0xee, 0xa0, 0xc6, 0x67, 0x2c, 0x59,
        0x67, 0x09, 0xa0, 0xfb, 0x57, 0x9b, 0x99, 0x77,  0x23, 0x68, 0xcf, 0xbe, 0xee, 0x60, 0x1b, 0xc2,
        0x07, 0x02, 0x14, 0xdf, 0xcb, 0x71, 0x15, 0x6f,  0x08, 0xcf, 0x19, 0x50, 0x96, 0xa4, 0x40, 0x6b,
        0xd7, 0x0b, 0xa2, 0x5d, 0x0d, 0x81, 0xb4, 0xb7,  0x43, 0x9c, 0x19, 0x93, 0xc6, 0x09, 0x2a, 0x7c,
        0x28, 0x29, 0x66, 0x95, 0x71, 0xd1, 0x0c, 0x40,  0x06, 0xbc, 0x21, 0xb8, 0x94, 0x28, 0xdb, 0x86,
        0x44, 0x68, 0x93, 0x9a, 0x06, 0xf6, 0xe2, 0x41,  0xb6, 0x01, 0xe7, 0x21, 0x7c, 0xa6, 0x8d, 0x02,
        0x85, 0xc0, 0x75, 0x7a, 0x1b, 0xbe, 0x45, 0x01,  0x1d, 0x20, 0xf1, 0x0b, 0x2c, 0x55, 0x9a, 0x18,
        0x56, 0x26, 0x0f, 0x00, 0x00, 0x09, 0x65, 0x4a,  0x4e, 0x42, 0xa4, 0x3c, 0xc3, 0x89, 0x93, 0x0b,
        0x0f, 0x43, 0x1e, 0xd7, 0x87, 0xdc, 0x9c, 0xe6,  0xd7, 0x01, 0x6e, 0x13, 0x68, 0x43, 0x1d, 0xe1,
        0x81, 0x1b, 0x9c, 0xc6, 0x0a, 0xb0, 0xbb, 0x35,  0xeb, 0xae, 0xa8, 0xed, 0xc5, 0xe4, 0x24, 0xb0,
        0x7a, 0xa5, 0x01, 0x7c, 0xc2, 0x92, 0x3d, 0xde,  0x6f, 0x55, 0x33, 0xab, 0x16, 0x06, 0x27, 0xc3,
        0xc9, 0x82, 0xdd, 0x7c, 0xca, 0x8c, 0xff, 0x4d,  0x2b, 0xa7, 0xd7, 0xf3, 0x4a, 0xf6, 0x74, 0x33,
        0xb0, 0xde, 0xad, 0x5f, 0xc5, 0x9c, 0x94, 0x42,  0xda, 0xf3, 0xe7, 0xc1, 0x02, 0x9f, 0x03, 0x52,
        0xbe, 0x78, 0x12, 0x8c, 0x4d, 0xd4, 0x02, 0x27,  0x84, 0x48, 0xd6, 0x73, 0x01, 0xe5, 0xd9, 0x50,
        0xf4, 0x29, 0x02, 0x0b, 0xc4, 0xca, 0x1f, 0x13,  0xb4, 0xa1, 0xf5, 0xcf, 0x07, 0x62, 0x37, 0xf4,
        0xbc, 0xd4, 0xf1, 0x4a, 0x82, 0x1b, 0xe6, 0x32,  0x3f, 0x2e, 0xac, 0x30, 0x45, 0x92, 0xe8, 0xca,
        0xc9, 0xf7, 0xef, 0xd0, 0x62, 0xce, 0x38, 0x40,  0xff, 0x7e, 0x5a, 0x0d, 0x9f, 0x40, 0x1d, 0xbd,
        0xb7, 0x38, 0x31, 0xe6, 0xe1, 0x4e, 0x31, 0x8a,  0x74, 0x2d, 0xa9, 0x31, 0xe0, 0x18, 0xa6, 0x3c,
        0x52, 0x7a, 0xf7, 0x83, 0xb6, 0x37, 0xea, 0x31,  0xa0, 0xf9, 0x22, 0x77, 0x95, 0xdf, 0x82, 0x44,
        0x40, 0x2c, 0x5d, 0xf0, 0x17, 0x81, 0x9b, 0xcc,  0x3a, 0xbd, 0x92, 0xb9, 0xd5, 0xf6, 0x95, 0x8a,
        0xab, 0xa6, 0xf5, 0x7c, 0xfb, 0xa7, 0xea, 0x87,  0x28, 0x7c, 0x29, 0x6d, 0x46, 0x96, 0xa8, 0x1d,
        0x3b, 0x24, 0xb0, 0x26, 0xff, 0x64, 0x30, 0x3d,  0x8c, 0xa2, 0x26, 0x47, 0x74, 0x2b, 0xa1, 0xf9,
        0x74, 0x4d, 0x16, 0x07, 0xa3, 0x70, 0xcf, 0x11,  0x4a, 0x27, 0x16, 0x3e, 0x64, 0x77, 0x6a, 0xb0,
        0x8b, 0x05, 0xe4, 0xc5, 0xef, 0x8d, 0x13, 0x7a,  0x8a, 0xc2, 0xc2, 0x41, 0x6e, 0x89, 0x53, 0x86,
        0xb7, 0x57, 0x42, 0x8d, 0xca, 0xd3
    };

    /* skip tcp length prefix */
    char *start = pkt + 2;
    size_t len = 0x04b6;



    assert_true(buf_write(&ctx->ciphertext, start, len));
    assert_true(tls_crypt_unwrap(&ctx->ciphertext, &ctx->unwrapped, &ctx->co));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(tls_crypt_loopback,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_loopback_zero_len,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_loopback_max_len,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_msg_too_long,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_invalid_key,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_fail_replay,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_ignore_replay,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_no_metadata,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_max_metadata,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_too_long_metadata,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_wrong_key,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(tls_crypt_v2_wrap_unwrap_dst_too_small,
                                        test_tls_crypt_v2_setup,
                                        test_tls_crypt_v2_teardown),
        cmocka_unit_test_setup_teardown(test_tls_crypt_secure_reneg_key,
                                        test_tls_crypt_setup,
                                        test_tls_crypt_teardown),
        cmocka_unit_test(test_tls_crypt_v2_write_server_key_file),
        cmocka_unit_test(test_tls_crypt_v2_write_client_key_file),
        cmocka_unit_test(test_tls_crypt_v2_write_client_key_file_metadata),
        cmocka_unit_test(test_tls_crypt_reynir),
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    int ret = cmocka_run_group_tests_name("tls-crypt tests", tests, NULL, NULL);

#if defined(ENABLE_CRYPTO_OPENSSL)
    EVP_cleanup();
#endif

    return ret;
}
