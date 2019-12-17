#ifndef NTTRU_KEM_H
#define NTTRU_KEM_H

#include "nttru-params.h"

int nttru_crypto_kem_keypair(unsigned char *pk, unsigned char *sk, RAND_STATE *rand);
int nttru_crypto_kem_enc(unsigned char *c,
        unsigned char *k,
        const unsigned char *pk, RAND_STATE *rand);
int nttru_crypto_kem_dec(unsigned char *k,
        const unsigned char *c,
        const unsigned char *sk);

#endif
