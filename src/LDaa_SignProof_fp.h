/*
 * MIT License
 *
 * Copyright (c) 2019 Luís Fiolhais, Paulo Martins, Leonel Sousa (INESC-ID)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef LDAA_SIGNPROOF_FP_H
#define LDAA_SIGNPROOF_FP_H

typedef struct {
    TPMI_DH_OBJECT             key_handle;
    UINT8                      sid;   // Session ID
    TPM2B_LDAA_SIGN_STATE      R1;
    TPM2B_LDAA_SIGN_STATE      R2;
    UINT8                      sign_state_sel;
    UINT8                      sign_state_type;
} LDAA_SignProof_In;

#define RC_LDAA_SignProof_key_handle		(TPM_RC_P + TPM_RC_1)
#define RC_LDAA_SignProof_sid		        (TPM_RC_P + TPM_RC_2)
#define RC_LDAA_SignProof_R1		        (TPM_RC_P + TPM_RC_3)
#define RC_LDAA_SignProof_R2		        (TPM_RC_P + TPM_RC_4)
#define RC_LDAA_SignProof_sign_state_sel	(TPM_RC_P + TPM_RC_5)
#define RC_LDAA_SignProof_sign_state_type	(TPM_RC_P + TPM_RC_6)

typedef struct {
    TPM2B_LDAA_SIGN_STATE      R1;
    TPM2B_LDAA_SIGN_STATE      R2;
    TPM2B_LDAA_SIGN_GROUP      sign_group;
} LDAA_SignProof_Out;

TPM_RC
TPM2_LDAA_SignProof(
         LDAA_SignProof_In      *in, // IN: input parameter list
		 LDAA_SignProof_Out     *out // OUT: output parameter list
		 );
#endif
