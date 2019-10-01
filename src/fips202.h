#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

typedef struct {
    uint64_t s[25];
} keccak_state;

void shake128_absorb(keccak_state *state, const unsigned char *input, unsigned int inputByteLen);
void shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, keccak_state *state);
void shake128_stream_init(keccak_state *sate, const unsigned char *seed, uint16_t nonce);

void shake256_absorb(keccak_state *state, const unsigned char *input, unsigned long long inlen);
void shake256_squeezeblocks(unsigned char *output, unsigned long nblocks, keccak_state *state);
void shake256_stream_init(keccak_state *state, const unsigned char *seed, uint16_t nonce);

void kyber_shake128_absorb(keccak_state *s, const unsigned char *input, unsigned char x, unsigned char y);
void kyber_shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, keccak_state *s);
void shake256_prf(unsigned char *output, unsigned long long outlen, const unsigned char *key, const unsigned char nonce);

typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

#endif
