#ifndef KYBER_KEYGEN_FP_H
#define KYBER_KEYGEN_FP_H

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
