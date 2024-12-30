#ifndef EPID_REVOKER
#define EPID_REVOKER

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128

// #include "pairing_3.h"
#include "epid_type.h"

// platform & verifier & revoker
struct PRLNode{
    Big f;
    PRLNode *next;
};

// platform & verifier & revoker
struct PRL{
    PRLNode *head;
    PRLNode *tail;
};

// SRLNode
struct BK{
    G3 B,K;
    BK *next;
};

// platform & verifier & revoker
struct SRL{
    BK *head;
    BK *tail;
};

// platform & revoker
struct Revoker_SK{
    G1 A;
    Big x,y,f;
};

// SigmaiNode
struct Revoker_BK_SPK{
    G3 B,K;
    Big c,sf;
};

// platform & verifier & revoker
struct Revoker_Sigma0{
    G3 B,K;
    G1 T;
    Big c,sf,sx,sa,sb;
};

struct Revoker_Sigmai{
    Revoker_BK_SPK *sigmai;
    int cnt;
};

// platform & verifier & revoker
struct Revoker_Sigma{
    Revoker_Sigma0 *sigma0;
    Revoker_Sigmai *sigmai;
};

void revokerPreCom(Public_PRL *pPRL, Public_SRL *pSRL);
int revokerVerify(GPK * gpk, char *m, Public_PRL *pRL, Revoker_Sigmai *sigmai, Revoker_Sigma0 *sigma0);

int revokerCheckPRL(PRL *pRL, G3 *B, G3 *K);
int revokerCheckSRL(GPK *gpk, char *m, Revoker_Sigmai *sigmai, G3 *B, G3 *K);

void revokerRevokePRL(GPK *gpk, Public_PRL *pRL, Revoker_SK *sk);
int revokerRevokeSRL(GPK *gpk, Public_PRL *pRL, Public_SRL *sRL, char *m, Revoker_Sigma *sigma);

#endif