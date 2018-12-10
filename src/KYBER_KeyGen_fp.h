#ifndef KYBER_KEYGEN_FP_H
#define KYBER_KEYGEN_FP_H

#define KYBER_SYMBYTES 32

#define KYBER_N 256
#define KYBER_Q 7681

#define KYBER_PUBLICKEYBYTES  736
#define KYBER_SECRETKEYBYTES  1632

#define KYBER_POLYBYTES              416
#define KYBER_POLYCOMPRESSEDBYTES    96

#define MAX_KYBER_K 4

typedef struct {
    BYTE	sec_sel; // Possible security values are 2 (512), 3 (768) and 4 (1024).
} KYBER_KeyGen_In;

#define RC_KYBER_KeyGen_sec_sel		(TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_KYBER_PUBLIC_KEY	public_key;
    TPM2B_KYBER_SECRET_KEY	secret_key;
} KYBER_KeyGen_Out;

TPM_RC
TPM2_KYBER_KeyGen(
         KYBER_KeyGen_In      *in,            // IN: input parameter list
		 KYBER_KeyGen_Out     *out            // OUT: output parameter list
		 );


#endif
