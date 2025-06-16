#include "epid_verifier.h"

GT vt1,vt2,vt3,vt4;

void verifierPreCom(GPK* gpk)
{
    initiate();
    pairing(&vt1,&gpk->g2,&gpk->g1);
	pairing(&vt2,&gpk->g2,&gpk->h1);
	pairing(&vt3,&gpk->g2,&gpk->h2);
	pairing(&vt4,&gpk->w,&gpk->h2);

}

int verifierCheckPRL(Public_PRL *pRL, G3 *B, G3 *K){
    for(int i=0;i<pRL->cnt;i++){
        G1 K1;
        // K≠B^fi
        pair_mult_G1(&K1, B, pRL->f[i]);
        if(G1_equals(&K1,K)){
            printf("pRL revoked!\n");
            return -1;
        }
    }
    return 0;
}

int verifierCheckSRL(GPK *gpk, char *m, Verifier_Sigmai *sigmai, G3 *B, G3 *K){
    for(int i=0;i<sigmai->cnt;i++){
        G3 Ri,tmp_G3;
        Big tmp_Big;
        // a)
        // Ri=Bi^sf·Ki^(-c)
        pair_mult_G1(&Ri, &sigmai->sigmai[i].B, &sigmai->sigmai[i].sf);
        BIG_modneg(tmp_Big, sigmai->sigmai[i].c,gpk->p);
        pair_mult_G1(&tmp_G3,&sigmai->sigmai[i].K,tmp_Big);
        G1_add(&Ri, &tmp_G3);

        // b)
        Big c;
        hash_SRLNode_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,B,K,&sigmai->sigmai[i].B,&sigmai->sigmai[i].K,&Ri,m);

        // c)
        if(!BIG_comp(c, sigmai->sigmai[i].c)){
            printf("sRL revoked!\n");
            return -1;
        }
    }
    return 0;
}

int verifierVerify(GPK *gpk, char *m, Public_PRL *pRL, Verifier_Sigmai *sigmai, Verifier_Sigma0 *sigma0)
{
    // 验证sigma0的知识证明

// 4.Verify -- 3)
    G3 R1,tmp_G3;
    Big tmp_Big;
    // R1=B^sf·K^(-c)
    pair_mult_G1(&R1, &sigma0->B, sigma0->sf);
    BIG_modneg(tmp_Big, sigma0->c,gpk->p);
    pair_mult_G1(&tmp_G3, &sigma0->K, tmp_Big);
    G1_add(&R1, &tmp_G3);

    //R2=e(T,g2^(-sx)·w^(-c))·T2^sf·T3^sb·T4^sa·T1^c
    GT R2,tmp_GT_1, tmp_GT_2,tmp_GT_3,tmp_GT_4;
    G2 tmp_G2_1,tmp_G2_2;
    G1 tmp_G1;
    BIG_modneg(tmp_Big, sigma0->sx,gpk->p);
    pair_mult_G2(&tmp_G2_1, &gpk->g2, tmp_Big);
    BIG_modneg(tmp_Big, sigma0->c,gpk->p);
    pair_mult_G2(&tmp_G2_2, &gpk->w, tmp_Big);
    G2_add(&tmp_G2_1, &tmp_G2_2);

    pairing(&R2,&tmp_G2_1,&sigma0->T);
    pair_power_GT(&tmp_GT_2, &vt2, sigma0->sf);
    pair_power_GT(&tmp_GT_3, &vt3, sigma0->sb);
    pair_power_GT(&tmp_GT_4, &vt4, sigma0->sa);
    pair_power_GT(&tmp_GT_1, &vt1, sigma0->c);
    GT_mul(&R2, &tmp_GT_2);
    GT_mul(&R2, &tmp_GT_3);
    GT_mul(&R2, &tmp_GT_4);
    GT_mul(&R2, &tmp_GT_1);

// 4.Verify -- 4)
    Big c;
    hash_sigma_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma0->B,&sigma0->K,&sigma0->T,&R1,&R2,m);

    printf("c caculate:\n");
    display_Big(c);
    printf("c extracted:\n");
    display_Big(sigma0->c);
    if(BIG_comp(c, sigma0->c))
    {
        printf("Verification failed, aborting..\n");
        return -2;
    }
//检查pRL和sRL
// 4.Verify -- 5)
    if(verifierCheckPRL(pRL, &sigma0->B, &sigma0->K))return -1;
// 4.Verify -- 6)
    if(verifierCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K))return -1;

    printf("Verification succeeds!\n");

    return 0;
}

void printVerifier_BK_SPK(Verifier_BK_SPK *sigmai){
    printf("        SigmaiNode\n");
    printf("            B--\n            ");
    display_G1(&sigmai->B);
    printf("            K--\n            ");
    display_G1(&sigmai->K);
    printf("            c--\n            ");
    display_Big(&sigmai->c);
    printf("            sf--\n            ");
    display_Big(&sigmai->sf);
}

void printVerifier_Sigma0(Verifier_Sigma0 *sigma0){
    printf("    Sigma0\n");
    printf("        B--\n       ");
    display_G1(&sigma0->B);
    printf("        K--\n       ");
    display_G1(&sigma0->K);
    printf("        T--\n       ");
    display_G1(&sigma0->T);
    printf("        c--\n       ");
    display_Big(&sigma0->c);
    printf("        sf--\n       ");
    display_Big(&sigma0->sf);
    printf("        sx--\n       ");
    display_Big(&sigma0->sx);
    printf("        sa--\n       ");
    display_Big(&sigma0->sa);
    printf("        sb--\n       ");
    display_Big(&sigma0->sb);
}

void printVerifier_Sigmai(Verifier_Sigmai *sigmai){
    printf("    Sigmai\n");
    for(int i=0;i<sigmai->cnt;i++){
        printVerifier_BK_SPK(sigmai->sigmai+i);
    }
}

void printVerifier_Sigma(Verifier_Sigma *sigma){
    printf("[sigma]VerifierRecieved: \n");
    printVerifier_Sigma0(&sigma->sigma0);
    printVerifier_Sigmai(&sigma->sigmai);
}