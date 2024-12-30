#ifndef EPID_PLATFORM
#define EPID_PLATFORM

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128

// #include "pairing_3.h"
#include "epid_type.h"

// platform & revoker
struct SK{
    G1 A;
    Big x,y,f;
};

// platform & issuer
struct Platform_CommC{
    G1 C;
    Big c,sf,sy1;
};

// platform & issuer
struct Platform_CRE{
    G1 A;
    Big x,y2;
};

// SigmaiNode
struct Platform_BK_SPK{
    G3 B,K;
    Big c,sf;
};

// platform & verifier & revoker
struct Platform_Sigma0{
    G3 B,K;
    G1 T;
    Big c,sf,sx,sa,sb;
};

struct Platform_Sigmai{
    Platform_BK_SPK *sigmai;
    int cnt;
};

// platform & verifier & revoker
struct Platform_Sigma{
    Platform_Sigma0 *sigma0;
    Platform_Sigmai *sigmai;
};

void platformInit();
void platformPreCom();
void platformJoin_1(GPK *gpk,Platform_CommC* commC);
int platformJoin_3(GPK *gpk, Platform_CRE *cre, PPK *ppk);
void platformSign(GPK *gpk, char *m, Public_SRL *sRL, Platform_Sigma* sigma);

SK* platformLeakSK_Test();

#endif