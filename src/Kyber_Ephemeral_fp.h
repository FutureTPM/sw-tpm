#ifndef KYBER_EPHEMERAL_FP_H
#define KYBER_EPHEMERAL_FP_H

typedef struct {
    TPMI_DH_OBJECT key_handle;
} Kyber_Ephemeral_In;

#define RC_Kyber_Ephemeral_key_handle	(TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_KYBER_PUBLIC_KEY public_key;
    TPM2B_KYBER_PUBLIC_KEY secret_key;
    TPM_KYBER_SECURITY     k;
} Kyber_Ephemeral_Out;

TPM_RC
TPM2_Kyber_Ephemeral(
		  Kyber_Ephemeral_In     *in,            // IN: input parameter list
		  Kyber_Ephemeral_Out    *out            // OUT: output parameter list
		  );

#endif
