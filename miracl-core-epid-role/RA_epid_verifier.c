#include "RA_epid_verifier.h"

GT vt1,vt2,vt3,vt4;

// PFC *verifierPFC=&pfc;
void verifierPreCom(GPK* gpk)
{
    initiate();
    // verifierPFC = PFC(AES_SECURITY);

    // verifierPFC->precomp_for_power(vt1);
    // verifierPFC->precomp_for_power(vt2);
    // verifierPFC->precomp_for_power(vt3);
    // verifierPFC->precomp_for_power(vt4);

    pairing(&vt1,&gpk->g2,&gpk->g1);
	pairing(&vt2,&gpk->g2,&gpk->h1);
	pairing(&vt3,&gpk->g2,&gpk->h2);
	pairing(&vt4,&gpk->w,&gpk->h2);

}

int verifierCheckPRL(Public_PRL *pRL, G3 *B, G3 *K){
    for(int i=0;i<pRL->cnt;i++){
        G1 K1;
        pair_mult_G1(&K1, B, pRL->f[i]);
        if(G1_equals(&K1,K)){
            // cout << "pRL revoked! " << endl;
            printf("pRL revoked!\n");
            return -1;
        }
    }
    return 0;
}

int verifierCheckSRL(GPK *gpk, char *m, Verifier_Sigmai *sigmai, G3 *B, G3 *K){
    for(int i=0;i<sigmai->cnt;i++){
        // Verifier_BK_SPK *s = &(sigmai->sigmai[i]);
        // G3 R = verifierPFC->mult(*B,s->sf)+verifierPFC->mult(*K,(-1) * s->c);
        // G3 Ri = verifierPFC->mult(s->B,s->sf)+verifierPFC->mult(s->K,(-1)*s->c);
        G3 R,Ri,tmp_G3;
        Big tmp_Big;
        pair_mult_G1(&R, B, sigmai->sigmai[i].sf);
        BIG_modneg(tmp_Big, sigmai->sigmai[i].c,gpk->p);
        pair_mult_G1(&tmp_G3,K,tmp_Big);
        G1_add(&R, &tmp_G3);
        pair_mult_G1(&Ri, &sigmai->sigmai[i].B, &sigmai->sigmai[i].sf);
        BIG_modneg(tmp_Big, sigmai->sigmai[i].c,gpk->p);
        pair_mult_G1(&tmp_G3,&sigmai->sigmai[i].K,tmp_Big);
        G1_add(&Ri, &tmp_G3);
        // verifierPFC->start_hash();
        // verifierPFC->add_to_hash(gpk->p);
        // verifierPFC->add_to_hash(gpk->g1);
        // verifierPFC->add_to_hash(gpk->g2);
        // verifierPFC->add_to_hash(gpk->g3);
        // verifierPFC->add_to_hash(gpk->h1);
        // verifierPFC->add_to_hash(gpk->h2);
        // verifierPFC->add_to_hash(gpk->w);
        // verifierPFC->add_to_hash(*B);
        // verifierPFC->add_to_hash(*K);
        // verifierPFC->add_to_hash(R);
        // verifierPFC->add_to_hash(s->B);
        // verifierPFC->add_to_hash(s->K);
        // verifierPFC->add_to_hash(Ri);
        // verifierPFC->add_to_hash(m);
        // Big c = verifierPFC->finish_hash_to_group();
        Big c;
        hash_SRLNode_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,B,K,&R,&sigmai->sigmai[i].B,&sigmai->sigmai[i].K,&Ri,m);

        // if(c == s->c){
        if(BIG_comp(c, sigmai->sigmai[i].c)){
            // cout << "sRL revoked! " << endl;
            printf("sRL revoked!\n");
            return -1;
        }
    }
    return 0;
}

int verifierVerify(GPK *gpk, char *m, Public_PRL *pRL, Verifier_Sigmai *sigmai, Verifier_Sigma0 *sigma0)
{
    // 验证sigma0的知识证明
    // G3 R1 = verifierPFC->mult(sigma0->B, sigma0->sf) + verifierPFC->mult(sigma0->K, (-1) * sigma0->c);
    G3 R1,tmp_G3;
    Big tmp_Big;
    pair_mult_G1(&R1, &sigma0->B, sigma0->sf);
    BIG_modneg(tmp_Big, sigma0->c,gpk->p);
    pair_mult_G1(&tmp_G3, &sigma0->K, tmp_Big);
    G1_add(&R1, &tmp_G3);

    // GT R2 = verifierPFC->pairing(verifierPFC->mult(gpk->g2, (-1) * sigma0->sx) + verifierPFC->mult(gpk->w, (-1) * sigma0->c), sigma0->T) 
    //* verifierPFC->power(vt2, sigma0->sf) 
    //* verifierPFC->power(vt3, sigma0->sb) 
    //* verifierPFC->power(vt4, sigma0->sa) 
    //* verifierPFC->power(vt1, sigma0->c);
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

    // verifierPFC->start_hash();
    // verifierPFC->add_to_hash(gpk->p);
    // verifierPFC->add_to_hash(gpk->g1);
    // verifierPFC->add_to_hash(gpk->g2);
    // verifierPFC->add_to_hash(gpk->g3);
    // verifierPFC->add_to_hash(gpk->h1);
    // verifierPFC->add_to_hash(gpk->h2);
    // verifierPFC->add_to_hash(gpk->w);
    // verifierPFC->add_to_hash(sigma0->B);
    // verifierPFC->add_to_hash(sigma0->K);
    // verifierPFC->add_to_hash(sigma0->T);
    // verifierPFC->add_to_hash(R1);
    // verifierPFC->add_to_hash(R2);
    // verifierPFC->add_to_hash(m);
    // Big c = verifierPFC->finish_hash_to_group();
    Big c;
    hash_sigma_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma0->B,&sigma0->K,&sigma0->T,&R1,&R2,m);

    printf("c caculate:\n");
    display_Big(c);
    printf("c extracted:\n");
    display_Big(sigma0->c);
    // if (c != sigma0->c)
    if(BIG_comp(c, sigma0->c))
    {
        // cout << "Verification failed, aborting.. " << endl;
        printf("Verification failed, aborting..\n");
        return -2;
    }
//检查pRL和sRL
    if(verifierCheckPRL(pRL, &sigma0->B, &sigma0->K))return -1;
    if(verifierCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K))return -1;

    // cout << "Verification succeeds! " << endl;
    printf("Verification succeeds!\n");

    return 0;
}

void printVerifier_BK_SPK(Verifier_BK_SPK *sigmai){
    // cout<<"type: Verifier_BK_SPK"<<endl;
    // cout<<"    B.g: "<<sigmai->B.g<<endl;
    // cout<<"        B size: "<<sizeof(sigmai->B)<<endl;
    // cout<<"    K.g: "<<sigmai->K.g<<endl;
    // cout<<"        K size: "<<sizeof(sigmai->K)<<endl;
    // cout<<"    c: "<<sigmai->c<<endl;
    // cout<<"        c len: "<<sigmai->c.len()<<endl;
    // cout<<"        c size: "<<sizeof(sigmai->c)<<endl;
    // cout<<"    sf: "<<sigmai->sf<<endl;
    // cout<<"        sf len: "<<sigmai->sf.len()<<endl;
    // cout<<"        sf size: "<<sizeof(sigmai->sf)<<endl;
    // cout<<"Verifier_BK_SPK size: "<<sizeof(*sigmai)<<endl;

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
    // cout<<"type: Verifier_Sigma0"<<endl;
    // cout<<"    B.g: "<<sigma0->B.g<<endl;
    // cout<<"        B size: "<<sizeof(sigma0->B)<<endl;
    // cout<<"    K.g: "<<sigma0->K.g<<endl;
    // cout<<"        K size: "<<sizeof(sigma0->K)<<endl;
    // cout<<"    T.g: "<<sigma0->T.g<<endl;
    // cout<<"        T size: "<<sizeof(sigma0->T)<<endl;
    // cout<<"    c: "<<sigma0->c<<endl;
    // cout<<"        c len: "<<sigma0->c.len()<<endl;
    // cout<<"        c size: "<<sizeof(sigma0->c)<<endl;
    // cout<<"Verifier_Sigma0 size: "<<sizeof(*sigma0)<<endl;
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
    // cout<<"type: Verifier_Sigmai"<<endl;
    // cout<<"    cnt: "<<sigmai->cnt<<endl;
    // for(int i=0;i<sigmai->cnt;i++){
    //     printVerifier_BK_SPK(&sigmai->sigmai[i]);
    // }
    // cout<<"Verifier_Sigmai size: "<<sizeof(*sigmai)<<endl;

    printf("    Sigmai\n");
    for(int i=0;i<sigmai->cnt;i++){
        printVerifier_BK_SPK(sigmai->sigmai+i);
    }
}

void printVerifier_Sigma(Verifier_Sigma *sigma){
    // cout<<"type: Verifier_Sigma"<<endl;
    // printVerifier_Sigma0(sigma->sigma0);
    // printVerifier_Sigmai(sigma->sigmai);
    // cout<<"Verifier_Sigma size: "<<sizeof(*sigma)<<endl;
    printf("[sigma]VerifierRecieved: \n");
    printVerifier_Sigma0(&sigma->sigma0);
    printVerifier_Sigmai(&sigma->sigmai);
}