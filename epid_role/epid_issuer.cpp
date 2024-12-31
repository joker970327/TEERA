#include "epid_issuer.h"

Big isk;
PFC *issuerPFC= &pfc;


void issuerSetup(GPK *gpk){
    // issuerPFC = PFC(AES_SECURITY);

    gpk->p = issuerPFC->order();
    issuerPFC->random(gpk->g1);
    issuerPFC->random(gpk->g2);
    issuerPFC->random(gpk->g3);
    issuerPFC->random(isk);
    issuerPFC->random(gpk->h1);
    issuerPFC->random(gpk->h2);
    gpk->w=issuerPFC->mult(gpk->g2, isk);

    issuerPFC->precomp_for_mult(gpk->g1);
    issuerPFC->precomp_for_mult(gpk->g2);
    issuerPFC->precomp_for_mult(gpk->g3);
    issuerPFC->precomp_for_mult(gpk->h1);
    issuerPFC->precomp_for_mult(gpk->h2);
    issuerPFC->precomp_for_mult(gpk->w);
    issuerPFC->precomp_for_pairing(gpk->g2);
}

void issuerJoin_2(GPK *gpk, Issuer_CommC *commC, Issuer_CRE* cre){
    //CRE *cre = (CRE*)malloc(sizeof(CRE));
    issuerPFC->random(cre->x);
    issuerPFC->random(cre->y2);
    cre->A = issuerPFC->mult(gpk->g1+commC->C+issuerPFC->mult(gpk->h2, cre->y2),inverse(cre->x+isk,gpk->p));
}