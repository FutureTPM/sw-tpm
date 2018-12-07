#ifndef KYBER_KEYGEN_FP_H
#define KYBER_KEYGEN_FP_H

#define KYBER_K 3

#define KYBER_SYMBYTES 32

#define KYBER_N 256
#define KYBER_Q 7681

#define KYBER_PUBLICKEYBYTES  736
#define KYBER_SECRETKEYBYTES  1632

#define KYBER_POLYBYTES              416
#define KYBER_POLYCOMPRESSEDBYTES    96
#define KYBER_POLYVECBYTES           (KYBER_K * KYBER_POLYBYTES)
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)

#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)

typedef struct {
    TPM2B_KYBER_PUBLIC_KEY	public_key;
    TPM2B_KYBER_SECRET_KEY	secret_key;
} KYBER_KeyGen_Out;

TPM_RC
TPM2_KYBER_KeyGen(
		 KYBER_KeyGen_Out     *out            // OUT: output parameter list
		 );


#endif
