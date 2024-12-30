#ifndef EPID_TYPE
#define EPID_TYPE

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128

#include "pairing_3.h"

extern PFC pfc;  // initialise pairing-friendly curve

typedef G1 G3;

// public
struct GPK{//群公钥
    Big p;
    G1 g1, h1, h2;
    G2 g2, w;
    G3 g3;
};

// public
struct PPK{
    G1 A;
    Big x,y;
};

struct Public_SRLNode{
    G3 B,K;
};

struct Public_SRL{
    Public_SRLNode *sRLNode;
    int cnt;
};

struct Public_PRL{
    Big *f;
    int cnt;
};

#endif