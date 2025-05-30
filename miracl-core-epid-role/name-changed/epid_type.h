#ifndef EPID_TYPE
#define EPID_TYPE

#include "epid_curve_BLS12383.h"

typedef G1 G3;

// public
typedef struct {//群公钥
    Big p;
    G1 g1, h1, h2;
    G2 g2, w;
    G3 g3;
}GPK;

// public
typedef struct {
    G1 A;
    Big x,y;
}PPK;

typedef struct {
    G3 B,K;
}Public_SRLNode;

typedef struct {
    Public_SRLNode *sRLNode;
    int cnt;
}Public_SRL;

typedef struct {
    Big *f;
    int cnt;
}Public_PRL;

void printGPK(GPK *gpk);
void printPPK(PPK *ppk);
void printPublic_SRLNode(Public_SRLNode *sRLNode);
void printPublic_SRL(Public_SRL *sRL);
void printPublic_PRL(Public_PRL *prl);

#endif