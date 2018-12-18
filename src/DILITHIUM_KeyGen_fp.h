#ifndef DILITHIUM_KEYGEN_FP_H
#define DILITHIUM_KEYGEN_FP_H

typedef struct {
    BYTE	mode;
} DILITHIUM_KeyGen_In;

#define RC_DILITHIUM_KeyGen_mode		(TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_DILITHIUM_PUBLIC_KEY	public_key;
    TPM2B_DILITHIUM_SECRET_KEY	secret_key;
} DILITHIUM_KeyGen_Out;

TPM_RC
TPM2_DILITHIUM_KeyGen(
         DILITHIUM_KeyGen_In      *in,            // IN: input parameter list
		 DILITHIUM_KeyGen_Out     *out            // OUT: output parameter list
		 );


#endif
