#ifndef EPID_ISSUER
#define EPID_ISSUER

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128

// #include "pairing_3.h"
#include "epid_type.h"

// signer & issuer
typedef struct {
    G1 C;
    Big c,sf,sy1;
}Issuer_CommC;

// signer & issuer
typedef struct {
    G1 A;
    Big x,y2;
}Issuer_CRE;

void issuerSetup(GPK *gpk);
void issuerJoin_2(GPK *gpk, Issuer_CommC *commC, Issuer_CRE* cre);

void printIssuer_CommC(Issuer_CommC *commC);
void printIssuer_CRE(Issuer_CRE *cre);
void printGPK(GPK *gpk);

#endif