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
#ifndef LDAA_COMMITTOKENLINK_FP_H
#define LDAA_COMMITTOKENLINK_FP_H

typedef struct {
    TPMI_DH_OBJECT             key_handle;
    UINT8                      sid;   // Session ID
    TPM2B_LDAA_BASENAME        bsn;
} LDAA_CommitTokenLink_In;

#define RC_LDAA_CommitTokenLink_key_handle	  (TPM_RC_P + TPM_RC_1)
#define RC_LDAA_CommitTokenLink_sid		      (TPM_RC_P + TPM_RC_2)
#define RC_LDAA_CommitTokenLink_bsn	          (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_LDAA_NYM             nym;
    TPM2B_LDAA_PE              pe;
    TPM2B_LDAA_PBSN            pbsn;
} LDAA_CommitTokenLink_Out;

TPM_RC
TPM2_LDAA_CommitTokenLink(
         LDAA_CommitTokenLink_In      *in, // IN: input parameter list
		 LDAA_CommitTokenLink_Out     *out // OUT: output parameter list
		 );
#endif
