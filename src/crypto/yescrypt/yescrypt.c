#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "yescrypt.h"

#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth 8
#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint32_t))
#define Sbytes (2 * ((1 << Swidth) * PWXsimple * 8))
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)

typedef struct {
    uint32_t *S;
    uint32_t (*S0)[2], (*S1)[2];
    size_t w;
} pwxform_ctx_t;

static void blkcpy(uint32_t *dst, const uint32_t *src, size_t count)
{
    do {
        *dst++ = *src++;
    } while (--count);
}

static void blkxor(uint32_t *dst, const uint32_t *src, size_t count)
{
    do {
        *dst++ ^= *src++;
    } while (--count);
}

static void salsa20(uint32_t B[16], uint32_t rounds)
{
    uint32_t x[16];
    size_t i;

    for (i = 0; i < 16; i++)
        x[i * 5 % 16] = B[i];

    for (i = 0; i < rounds; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
        x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
        x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
        x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
        x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
    }

    for (i = 0; i < 16; i++)
        B[i] += x[i * 5 % 16];
}

static void blockmix_salsa(uint32_t *B, uint32_t rounds)
{
    uint32_t X[16];
    size_t i;

    blkcpy(X, &B[16], 16);

    for (i = 0; i < 2; i++) {
        blkxor(X, &B[i * 16], 16);
        salsa20(X, rounds);
        blkcpy(&B[i * 16], X, 16);
    }
}

static void pwxform(uint32_t *B, pwxform_ctx_t *ctx)
{
    uint32_t (*X)[PWXsimple][2] = (uint32_t (*)[PWXsimple][2])B;
    uint32_t (*S0)[2] = ctx->S0, (*S1)[2] = ctx->S1;
    size_t i, j, k;

    for (i = 0; i < PWXrounds; i++) {
        for (j = 0; j < PWXgather; j++) {
            uint32_t xl = X[j][0][0];
            uint32_t xh = X[j][0][1];
            uint32_t (*p0)[2], (*p1)[2];

            p0 = S0 + (xl & Smask) / sizeof(*S0);
            p1 = S1 + (xh & Smask) / sizeof(*S1);

            for (k = 0; k < PWXsimple; k++) {
                uint64_t x, s0, s1;

                s0 = ((uint64_t)p0[k][1] << 32) + p0[k][0];
                s1 = ((uint64_t)p1[k][1] << 32) + p1[k][0];

                xl = X[j][k][0];
                xh = X[j][k][1];

                x = (uint64_t)xh * xl;
                x += s0;
                x ^= s1;

                X[j][k][0] = x;
                X[j][k][1] = x >> 32;
            }
        }
    }
}

static void blockmix_pwxform(uint32_t *B, pwxform_ctx_t *ctx, size_t r)
{
    uint32_t X[PWXwords];
    size_t r1, i;

    r1 = 128 * r / PWXbytes;

    blkcpy(X, &B[(r1 - 1) * PWXwords], PWXwords);

    for (i = 0; i < r1; i++) {
        if (r1 > 1)
            blkxor(X, &B[i * PWXwords], PWXwords);
        pwxform(X, ctx);
        blkcpy(&B[i * PWXwords], X, PWXwords);
    }

    i = (r1 - 1) * PWXbytes / 64;
    salsa20(&B[i * 16], 8);

    for (i++; i < 2 * r; i++) {
        blkxor(&B[i * 16], &B[(i - 1) * 16], 16);
        salsa20(&B[i * 16], 8);
    }
}

static uint32_t integerify(const uint32_t *B, size_t r)
{
    const uint32_t *X = &B[(2 * r - 1) * 16];
    return X[0];
}

static uint32_t p2floor(uint32_t x)
{
    uint32_t y;
    while ((y = x & (x - 1)))
        x = y;
    return x;
}

static uint32_t wrap(uint32_t x, uint32_t i)
{
    uint32_t n = p2floor(i);
    return (x & (n - 1)) + (i - n);
}

static void smix1(uint32_t *B, size_t r, uint32_t N,
    uint32_t *V, uint32_t *X, pwxform_ctx_t *ctx, int sbox_init)
{
    size_t s = 32 * r;
    uint32_t i, j;
    size_t k;

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            X[k * 16 + i] = B[k * 16 + (i * 5 % 16)];

    for (i = 0; i < N; i++) {
        blkcpy(&V[i * s], X, s);

        if (i > 1) {
            j = wrap(integerify(X, r), i);
            blkxor(X, &V[j * s], s);
        }

        if (!sbox_init)
            blockmix_pwxform(X, ctx, r);
        else
            blockmix_salsa(X, 8);
    }

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            B[k * 16 + (i * 5 % 16)] = X[k * 16 + i];
}

static void smix2(uint32_t *B, size_t r, uint32_t N, uint32_t Nloop,
    uint32_t *V, uint32_t *X, pwxform_ctx_t *ctx)
{
    size_t s = 32 * r;
    uint32_t i, j;
    size_t k;

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            X[k * 16 + i] = B[k * 16 + (i * 5 % 16)];

    for (i = 0; i < Nloop; i++) {
        j = integerify(X, r) & (N - 1);
        blkxor(X, &V[j * s], s);
        if (Nloop != 2)
            blkcpy(&V[j * s], X, s);
        blockmix_pwxform(X, ctx, r);
    }

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            B[k * 16 + (i * 5 % 16)] = X[k * 16 + i];
}

static void smix(uint32_t *B, size_t r, uint32_t N,
    uint32_t *V, uint32_t *X, pwxform_ctx_t *ctx)
{
    uint32_t Nloop_all = (N + 2) / 3;
    uint32_t Nloop_rw = Nloop_all;

    Nloop_all++; Nloop_all &= ~(uint32_t)1;
    Nloop_rw &= ~(uint32_t)1;

    smix1(B, 1, Sbytes / 128, ctx->S, X, ctx, 1);
    smix1(B, r, N, V, X, ctx, 0);
    smix2(B, r, N, Nloop_rw, V, X, ctx);
    smix2(B, r, N, Nloop_all - Nloop_rw, V, X, ctx);
}

int yescrypt_hash(const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen,
    uint8_t *buf, size_t buflen)
{
    uint32_t N = 4096;
    uint32_t r = 32;
    const uint8_t *pers = (const uint8_t *)"WaviBanana";
    size_t perslen = 10;

    size_t B_size, V_size;
    uint32_t *B, *V, *X, *S;
    pwxform_ctx_t ctx;
    uint32_t sha256[8];

    B_size = (size_t)128 * r;
    V_size = B_size * N;

    V = (uint32_t *)malloc(V_size);
    if (!V) return -1;
    B = (uint32_t *)malloc(B_size);
    if (!B) { free(V); return -1; }
    X = (uint32_t *)malloc(B_size);
    if (!X) { free(B); free(V); return -1; }
    S = (uint32_t *)malloc(Sbytes);
    if (!S) { free(X); free(B); free(V); return -1; }

    ctx.S = S;
    ctx.S0 = (uint32_t (*)[2])S;
    ctx.S1 = ctx.S0 + (1 << Swidth) * PWXsimple;
    ctx.w = 0;

    SHA256_Buf(passwd, passwdlen, (uint8_t *)sha256);

    PBKDF2_SHA256((uint8_t *)sha256, sizeof(sha256),
        salt, saltlen, 1, (uint8_t *)B, B_size);

    blkcpy(sha256, B, sizeof(sha256) / sizeof(sha256[0]));

    smix(B, r, N, V, X, &ctx);

    PBKDF2_SHA256((uint8_t *)sha256, sizeof(sha256),
        (uint8_t *)B, B_size, 1, buf, buflen);

    {
        uint32_t hmac_result[8];
        HMAC_SHA256_Buf(buf, buflen, pers, perslen, (uint8_t *)hmac_result);
        SHA256_Buf(hmac_result, sizeof(hmac_result), buf);
    }

    free(S);
    free(X);
    free(B);
    free(V);

    return 0;
}
