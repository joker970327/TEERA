#ifndef EPID_VERIFIER
#define EPID_VERIFIER

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128

#include "pairing_3.h"
#include "epid_type.h"

void verifierCheckPRL(PRL *pRL, G3 *B, G3 *K);
void verifierCheckSRL(GPK *gpk, char *m, Sigmai *sigmai, G3 *B, G3 *K);

void verifierPreCom();
void verifierVerify(GPK * gpk, char *m, PRL *pRL, Sigmai *sigmai, Sigma0 *sigma0);

#endif