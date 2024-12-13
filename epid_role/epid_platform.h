#ifndef EPID_PLATFORM
#define EPID_PLATFORM

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128

#include "pairing_3.h"
#include "epid_type.h"

void platformInit();
void platformPreCom();
CommC* platformJoin_1(GPK *gpk);
PPK* platformJoin_3(GPK *gpk, CRE *cre);
Sigma* platformSign(GPK *gpk, char *m,SRL *sRL);

#endif