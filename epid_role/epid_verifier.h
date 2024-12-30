#ifndef EPID_VERIFIER
#define EPID_VERIFIER

#include "epid_type.h"

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128


// SigmaiNode
struct Verifier_BK_SPK{
    G3 B,K;
    Big c,sf;
};

// platform & verifier & revoker
struct Verifier_Sigma0{
    G3 B,K;
    G1 T;
    Big c,sf,sx,sa,sb;
};

struct Verifier_Sigmai{
    Verifier_BK_SPK *sigmai;
    int cnt;
};

// platform & verifier & revoker
struct Verifier_Sigma{
    Verifier_Sigma0 *sigma0;
    Verifier_Sigmai *sigmai;
};

int verifierCheckPRL(Public_PRL *pRL, G3 *B, G3 *K);
int verifierCheckSRL(GPK *gpk, char *m, Verifier_Sigmai *sigmai, G3 *B, G3 *K);

void verifierPreCom();
int verifierVerify(GPK * gpk, char *m, Public_PRL *pRL, Verifier_Sigmai *sigmai, Verifier_Sigma0 *sigma0);

#endif