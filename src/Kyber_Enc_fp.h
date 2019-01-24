#ifndef KYBER_ENC_FP_H
#define KYBER_ENC_FP_H

typedef struct {
    TPMI_DH_OBJECT key_handle;
} Kyber_Encapsulate_In;

#define RC_Kyber_Encapsulate_key_handle		(TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_KYBER_SHARED_KEY	shared_key;
    TPM2B_KYBER_CIPHER_TEXT	cipher_text;
} Kyber_Encapsulate_Out;

TPM_RC
TPM2_Kyber_Enc(
         Kyber_Encapsulate_In      *in, // IN: input parameter list
		 Kyber_Encapsulate_Out     *out // OUT: output parameter list
		 );

#endif
