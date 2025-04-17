#ifndef EPID_VERIFIER
#define EPID_VERIFIER

#include "RA_epid_type.h"

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128


// SigmaiNode
typedef struct {
    G3 B,K;
    Big c,sf;
}Verifier_BK_SPK;

// platform & verifier & revoker
typedef struct {
    G3 B,K;
    G1 T;
    Big c,sf,sx,sa,sb;
}Verifier_Sigma0;

typedef struct {
    Verifier_BK_SPK *sigmai;
    int cnt;
}Verifier_Sigmai;

// platform & verifier & revoker
typedef struct {
    Verifier_Sigma0 sigma0;
    Verifier_Sigmai sigmai;
}Verifier_Sigma;

int verifierCheckPRL(Public_PRL *pRL, G3 *B, G3 *K);
int verifierCheckSRL(GPK *gpk, char *m, Verifier_Sigmai *sigmai, G3 *B, G3 *K);

void verifierPreCom(GPK* gpk);
int verifierVerify(GPK * gpk, char *m, Public_PRL *pRL, Verifier_Sigmai *sigmai, Verifier_Sigma0 *sigma0);

void printVerifier_BK_SPK(Verifier_BK_SPK *sigmai);
void printVerifier_Sigma0(Verifier_Sigma0 *sigma0);
void printVerifier_Sigmai(Verifier_Sigmai *sigmai);
void printVerifier_Sigma(Verifier_Sigma *sigma);

#endif