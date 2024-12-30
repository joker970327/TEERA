#ifndef EPID_ISSUER
#define EPID_ISSUER

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128

// #include "pairing_3.h"
#include "epid_type.h"

// platform & issuer
struct Issuer_CommC{
    G1 C;
    Big c,sf,sy1;
};

// platform & issuer
struct Issuer_CRE{
    G1 A;
    Big x,y2;
};

void issuerSetup(GPK *gpk);
void issuerJoin_2(GPK *gpk, Issuer_CommC *commC, Issuer_CRE* cre);

#endif