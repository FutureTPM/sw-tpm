#ifndef KYBER_3PHASE_KEX_FP_H
#define KYBER_3PHASE_KEX_FP_H

typedef struct {
    TPMI_DH_OBJECT          static_key;
    TPMI_DH_OBJECT          ephemeral_key;
    TPM2B_KYBER_CIPHER_TEXT cipher_text_1;
    TPM2B_KYBER_CIPHER_TEXT cipher_text_2;
    TPM2B_KYBER_SHARED_KEY  shared_key_3;
} Kyber_3Phase_KEX_In;

#define RC_Kyber_3Phase_KEX_static_key	            (TPM_RC_P + TPM_RC_1)
#define RC_Kyber_3Phase_KEX_ephemeral_key           (TPM_RC_P + TPM_RC_2)
#define RC_Kyber_3Phase_KEX_cipher_text_1	        (TPM_RC_P + TPM_RC_3)
#define RC_Kyber_3Phase_KEX_cipher_text_2	        (TPM_RC_P + TPM_RC_4)
#define RC_Kyber_3Phase_KEX_shared_key_3	        (TPM_RC_P + TPM_RC_5)

typedef struct {
    TPM2B_KYBER_SHARED_KEY  shared_key;
} Kyber_3Phase_KEX_Out;

TPM_RC
TPM2_Kyber_3Phase_KEX(
		  Kyber_3Phase_KEX_In     *in,            // IN: input parameter list
		  Kyber_3Phase_KEX_Out    *out            // OUT: output parameter list
		  );

#endif
