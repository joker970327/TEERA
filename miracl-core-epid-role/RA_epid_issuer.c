#include "RA_epid_issuer.h"

Big isk;

void issuerSetup(GPK *gpk){

    initiate();
// TMP
    order(gpk->p);
    random_G1_generator(&gpk->g1);
    random_G2_generator(&gpk->g2);
    random_G1_generator(&gpk->g3);
    random_Big(isk);
    random_G1(&gpk->h1);
    random_G1(&gpk->h2);
    pair_mult_G2(&gpk->w, &gpk->g2, isk);
}

void issuerJoin_2(GPK *gpk, Issuer_CommC *commC, Issuer_CRE* cre){
    random_Big(cre->x);
    random_Big(cre->y2);

    // A=(g1*C*h2^y2)^(1/(x+isk))
    G1_copy(&cre->A,&gpk->g1);
	G1_add(&cre->A,&commC->C);

    G1 tmp_G1_1;
    pair_mult_G1(&tmp_G1_1,&gpk->h2,cre->y2);
    G1_add(&cre->A,&tmp_G1_1);

    Big tmp_Big_2,tmp_Big_3;
	modadd(tmp_Big_2,cre->x,isk,gpk->p);
	BIG_invmodp(tmp_Big_3,tmp_Big_2,gpk->p);
	pair_mult_G1(&cre->A,&cre->A,tmp_Big_3);

    G1 poc;
    pair_mult_G1(&poc,&gpk->h1,commC->sf);
    pair_mult_G1(&tmp_G1_1,&gpk->h2,commC->sy1);
    G1_add(&poc,&tmp_G1_1);
    pair_mult_G1(&tmp_G1_1,&commC->C,commC->c);
    G1_add(&poc,&tmp_G1_1);

    Big cc;
    hash_comm_epid(cc,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&commC->C,&poc);

    if(BIG_comp(cc,commC->c)!=0){
        printf("comm verify failed!\n");
        return;
    }
}

void printIssuer_CommC(Issuer_CommC *commC){
    printf("[comm]IssuerRecieved: \n");
	printf("    C--\n    ");
	display_G1(&commC->C);
	printf("    c--\n    ");
	display_Big(commC->c);
	printf("    sf--\n    ");
	display_Big(commC->sf);
	printf("    sy1--\n    ");
	display_Big(commC->sy1);
}

void printIssuer_CRE(Issuer_CRE *cre){
    printf("[cre]IssuerSend: \n");
	printf("    A--\n   ");
	display_G1(&cre->A);
	printf("    x--\n   ");
	display_Big(cre->x);
    printf("    y2--\n  ");
    display_Big(cre->y2);
}

void printGPK(GPK *gpk){
    printf("[GPK]IssuerSet:\n");
    printf("    p--\n    ");
    display_Big(gpk->p);
    printf("    g1--\n    ");
    display_G1(&gpk->g1);
    printf("    h1--\n    ");
    display_G1(&gpk->h1);
    printf("    h2--\n    ");
    display_G1(&gpk->h2);
    printf("    g2--\n    ");
    display_G2(&gpk->g2);
    printf("    w--\n    ");
    display_G2(&gpk->w);
    printf("    g3--\n    ");
    display_G1(&gpk->g3);
}