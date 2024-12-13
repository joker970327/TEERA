#include "epid_issuer.h"

Big isk;

void issuerSetup(GPK *gpk){
    gpk->p = pfc.order();
    pfc.random(gpk->g1);
    pfc.random(gpk->g2);
    pfc.random(gpk->g3);
    pfc.random(isk);
    pfc.random(gpk->h1);
    pfc.random(gpk->h2);
    gpk->w=pfc.mult(gpk->g2, isk);

    pfc.precomp_for_mult(gpk->g1);
    pfc.precomp_for_mult(gpk->g2);
    pfc.precomp_for_mult(gpk->g3);
    pfc.precomp_for_mult(gpk->h1);
    pfc.precomp_for_mult(gpk->h2);
    pfc.precomp_for_mult(gpk->w);
    pfc.precomp_for_pairing(gpk->g2);
}

CRE* issuerJoin_2(GPK *gpk, CommC *commC){
    //CRE *cre = (CRE*)malloc(sizeof(CRE));
    CRE *cre = new CRE();
    pfc.random(cre->x);
    pfc.random(cre->y2);
    cre->A = pfc.mult(gpk->g1+commC->C+pfc.mult(gpk->h2, cre->y2),inverse(cre->x+isk,gpk->p));
    return cre;
}