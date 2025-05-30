#ifndef EPID_PLATFORM
#define EPID_PLATFORM

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128

// #include "pairing_3.h"
#include "epid_type.h"

// signer & revokeManager
typedef struct {
    G1 A;
    Big x,y,f;
}SK;

// signer & issuer
typedef struct {
    G1 C;
    Big c,sf,sy1;
}Platform_CommC;

// signer & issuer
typedef struct {
    G1 A;
    Big x,y2;
}Platform_CRE;

// SigmaiNode
typedef struct {
    G3 B,K;
    Big c,sf;
}Platform_BK_SPK;

// signer & verifier & revokeManager
typedef struct {
    G3 B,K;
    G1 T;
    Big c,sf,sx,sa,sb;
}Platform_Sigma0;

typedef struct {
    Platform_BK_SPK *sigmai;
    int cnt;
}Platform_Sigmai;

// signer & verifier & revokeManager
typedef struct {
    Platform_Sigma0 sigma0;
    Platform_Sigmai sigmai;
}Platform_Sigma;

void signerInit();
void signerPreCom(GPK *gpk);
void signerJoin_1(GPK *gpk,Platform_CommC* commC);
int signerJoin_3(GPK *gpk, Platform_CRE *cre, PPK *ppk);
void signerSign(GPK *gpk, char *m, Public_SRL *sRL, Platform_Sigma* sigma);

SK* signerLeakSK_Test();

void printSK();
void printPlatformCommC(Platform_CommC* commC);
void printPlatformCRE(Platform_CRE* cre);
void printPlatformBKSPK(Platform_BK_SPK* bk_spk);
void printPlatformSigma0(Platform_Sigma0* sigma0);
void printPlatformSigmai(Platform_Sigmai* sigmai);
void printPlatformSigma(Platform_Sigma* sigma);
void printPPK(PPK *ppk);

#endif