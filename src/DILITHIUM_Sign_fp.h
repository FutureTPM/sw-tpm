#ifndef DILITHIUM_SIGN_FP_H
#define DILITHIUM_SIGN_FP_H

typedef struct {
    BYTE	                    mode;
    TPM2B_DILITHIUM_MESSAGE	    message;
    TPM2B_DILITHIUM_SECRET_KEY	secret_key;
} DILITHIUM_Sign_In;

#define RC_DILITHIUM_Sign_mode		    (TPM_RC_P + TPM_RC_1)
#define RC_DILITHIUM_Sign_message		(TPM_RC_P + TPM_RC_2)
#define RC_DILITHIUM_Sign_secret_key	(TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_DILITHIUM_SIGNED_MESSAGE	signed_message;
} DILITHIUM_Sign_Out;

TPM_RC
TPM2_DILITHIUM_Sign(
         DILITHIUM_Sign_In      *in,            // IN: input parameter list
		 DILITHIUM_Sign_Out     *out            // OUT: output parameter list
		 );


#endif
