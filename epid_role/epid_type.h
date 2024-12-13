#ifndef EPID_TYPE
#define EPID_TYPE

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128

#include "pairing_3.h"

extern PFC pfc;  // initialise pairing-friendly curve

typedef G1 G3;

struct GPK{//群公钥
    Big p;
    G1 g1, h1, h2;
    G2 g2, w;
    G3 g3;
};

struct SK{
    G1 A;
    Big x,y,f;
};

struct PPK{
    G1 A;
    Big x,y;
};

struct CommC{
    G1 C;
    Big c,sf,sy1;
};

struct CRE{
    G1 A;
    Big x,y2;
};

struct BK{
    G3 B,K;
    BK *next;
};

struct SRL{
    BK *head;
    BK *tail;
};

struct BK_SPK{
    G3 B,K;
    Big c,sf;
    BK_SPK *next;
};

struct Sigma0{
    G3 B,K;
    G1 T;
    Big c,sf,sx,sa,sb;
};

struct Sigmai{
    BK_SPK *head;
    BK_SPK *tail;
};

struct Sigma{
    Sigma0 *sigma0;
    Sigmai *sigmai;
};

struct PRLNode{
    Big f;
    PRLNode *next;
};

struct PRL{
    PRLNode *head;
    PRLNode *tail;
};

#endif