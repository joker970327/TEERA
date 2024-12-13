#ifndef EPID_REVOKER
#define EPID_REVOKER

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128

#include "pairing_3.h"
#include "epid_type.h"

void revokerPreCom();
void revokerVerify(GPK * gpk, char *m, PRL *pRL, Sigmai *sigmai, Sigma0 *sigma0);

void revokerCheckPRL(PRL *pRL, G3 *B, G3 *K);
void revokerCheckSRL(GPK *gpk, char *m, Sigmai *sigmai, G3 *B, G3 *K);

void revokerRevokePRL(GPK *gpk, PRL *pRL, SK *sk);
void revokerRevokeSRL(GPK *gpk, PRL *pRL, SRL *sRL, char *m, Sigma *sigma);

#endif