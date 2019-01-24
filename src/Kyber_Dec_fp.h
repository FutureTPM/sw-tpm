#ifndef KYBER_DEC_FP_H
#define KYBER_DEC_FP_H

typedef struct {
    TPMI_DH_OBJECT	key_handle;
    TPM2B_KYBER_CIPHER_TEXT	cipher_text;
} Kyber_Decapsulate_In;

#define RC_Kyber_Decapsulate_key_handle		(TPM_RC_P + TPM_RC_1)
#define RC_Kyber_Decapsulate_cipher_text	(TPM_RC_P + TPM_RC_2)

typedef struct {
    TPM2B_KYBER_SHARED_KEY	shared_key;
} Kyber_Decapsulate_Out;

TPM_RC
TPM2_Kyber_Dec(
         Kyber_Decapsulate_In      *in,            // IN: input parameter list
		 Kyber_Decapsulate_Out     *out            // OUT: output parameter list
		 );

#endif
