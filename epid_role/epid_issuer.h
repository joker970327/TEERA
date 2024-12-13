#ifndef EPID_ISSUER
#define EPID_ISSUER

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128

#include "pairing_3.h"
#include "epid_type.h"

void issuerSetup(GPK *gpk);
CRE* issuerJoin_2(GPK *gpk, CommC *commC);

#endif