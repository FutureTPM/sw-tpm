#ifndef NTTRU_CRYPTO_STREAM_H
#define NTTRU_CRYPTO_STREAM_H

int nttru_crypto_stream(unsigned char *out,
        unsigned long long len,
        const unsigned char nonce[16],
        const unsigned char key[32]);

#endif
