#ifndef EPID_REVOKER
#define EPID_REVOKER

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128

// #include "pairing_3.h"
#include "epid_type.h"

// signer & verifier & revokeManager
typedef struct PRLNode{
    Big f;
    struct PRLNode *next;
}PRLNode;

// signer & verifier & revokeManager
typedef struct {
    PRLNode *head;
    PRLNode *tail;
}PRL;

// SRLNode
typedef struct BK{
    G3 B,K;
    struct BK *next;
}BK;

// signer & verifier & revokeManager
typedef struct {
    BK *head;
    BK *tail;
}SRL;

// signer & revokeManager
typedef struct {
    G1 A;
    Big x,y,f;
}Revoker_SK;

// SigmaiNode
typedef struct {
    G3 B,K;
    Big c,sf;
}Revoker_BK_SPK;

// signer & verifier & revokeManager
typedef struct {
    G3 B,K;
    G1 T;
    Big c,sf,sx,sa,sb;
}Revoker_Sigma0;

typedef struct {
    Revoker_BK_SPK *sigmai;
    int cnt;
}Revoker_Sigmai;

// signer & verifier & revokeManager
typedef struct {
    Revoker_Sigma0 sigma0;
    Revoker_Sigmai sigmai;
}Revoker_Sigma;

void revokeManagerPreCom(GPK* gpk, Public_PRL *pPRL, Public_SRL *pSRL);
// int revokeManagerVerify(GPK * gpk, char *m, Public_PRL *pRL, Revoker_Sigmai *sigmai, Revoker_Sigma0 *sigma0);

// int revokeManagerCheckPRL(Public_PRL *pRL, G3 *B, G3 *K);
// int revokeManagerCheckSRL(GPK *gpk, char *m, Revoker_Sigmai *sigmai, G3 *B, G3 *K);

void revokeManagerRevokePRL(GPK *gpk, Public_PRL *pRL, Revoker_SK *sk);
int revokeManagerRevokeSRL(GPK *gpk, Public_PRL *pRL, Public_SRL *sRL, char *m, Revoker_Sigma *sigma);

void printPRLNode(PRLNode *pRLNode);
void printPRL(PRL *pRL);
void printBK(BK *bk);
void printSRL(SRL *sRL);
void printRevoker_SK(Revoker_SK *sk);
void printRevoker_BK_SPK(Revoker_BK_SPK *sigmai);
void printRevoker_Sigma0(Revoker_Sigma0 *sigma0);
void printRevoker_Sigmai(Revoker_Sigmai *sigmai);
void printRevoker_Sigma(Revoker_Sigma *sigma);


#endif