#include "RA_epid_revoker.h"

GT rt1,rt2,rt3,rt4;
SRL *sRL;
PRL *pRL;
// PFC *revokerPFC = &pfc;

void setPRL(Public_PRL *pPRL){    
    PRLNode *p = pRL->head;
    int c;
    if(p != NULL){
        c = 1;
    }
    else{return;}
    while(p->next){
        c++;
        p = p->next;
    }
    p = pRL->head;
    // delete(pPRL->f);
    pPRL->f = NULL;
    // pPRL->f = new Big[c];
    pPRL->f = (Big*)malloc(c*sizeof(Big));
    for(int i=0;i<c;i++){
        // pPRL->f[i] = p->f;
        BIG_copy(pPRL->f[i],p->f);
        p = p->next;
    }
    pPRL->cnt = c;
}

void setSRL(Public_SRL *pSRL){
    BK *q = sRL->head;
    int c;
    if(q != NULL){
        c = 1;
    }
    else{return;}
    while(q->next){
        c++;
        q = q->next;
    }
    q = sRL->head;
    // delete(pSRL->sRLNode);
    pSRL->sRLNode = NULL;
    // pSRL->sRLNode = new Public_SRLNode[c];
    pSRL->sRLNode = (Public_SRLNode*)malloc(c*sizeof(Public_SRLNode));
    for(int i=0;i<c;i++){
        // pSRL->sRLNode[i].B = q->B;
        // pSRL->sRLNode[i].K = q->K;
        BIG_copy(&pSRL->sRLNode[i].B,&q->B);
        BIG_copy(&pSRL->sRLNode[i].K,&q->K);
        q = q->next;
    }
    pSRL->cnt = c;
}

void revokerPreCom(GPK *gpk, Public_PRL *pPRL, Public_SRL *pSRL)
{
    // initiate();
    // revokerPFC = PFC(AES_SECURITY);
    pRL = (PRL*)malloc(sizeof(PRL));
    sRL = (SRL*)malloc(sizeof(SRL));

    // revokerPFC->precomp_for_power(rt1);
    // revokerPFC->precomp_for_power(rt2);
    // revokerPFC->precomp_for_power(rt3);
    // revokerPFC->precomp_for_power(rt4);

    pairing(&rt1,&gpk->g2,&gpk->g1);
	pairing(&rt2,&gpk->g2,&gpk->h1);
	pairing(&rt3,&gpk->g2,&gpk->h2);
	pairing(&rt4,&gpk->w,&gpk->h2);

    setPRL(pPRL);
    setSRL(pSRL);
}

int revokerCheckPRL(Public_PRL *pRL, G3 *B, G3 *K){
    // for(int i=0;i<pRL->cnt;i++){
    //     if(*K==revokerPFC->mult(*B,pRL->f[i])){
    //         cout << "pRL revoked! " << endl;
    //         return -1;
    //     }
    // }
    // return 0;
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

int revokerCheckSRL(GPK *gpk, char *m, Revoker_Sigmai *sigmai, G3 *B, G3 *K){
    for(int i=0;i<sigmai->cnt;i++){
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
        // Revoker_BK_SPK *s = &(sigmai->sigmai[i]);
        // G3 R = revokerPFC->mult(*B,s->sf)+revokerPFC->mult(*K,(-1) * s->c);
        // G3 Ri = revokerPFC->mult(s->B,s->sf)+revokerPFC->mult(s->K,(-1)*s->c);
        // revokerPFC->start_hash();
        // revokerPFC->add_to_hash(gpk->p);
        // revokerPFC->add_to_hash(gpk->g1);
        // revokerPFC->add_to_hash(gpk->g2);
        // revokerPFC->add_to_hash(gpk->g3);
        // revokerPFC->add_to_hash(gpk->h1);
        // revokerPFC->add_to_hash(gpk->h2);
        // revokerPFC->add_to_hash(gpk->w);
        // revokerPFC->add_to_hash(*B);
        // revokerPFC->add_to_hash(*K);
        // revokerPFC->add_to_hash(R);
        // revokerPFC->add_to_hash(s->B);
        // revokerPFC->add_to_hash(s->K);
        // revokerPFC->add_to_hash(Ri);
        // revokerPFC->add_to_hash(m);
        // Big c = revokerPFC->finish_hash_to_group();
        Big c;
        hash_SRLNode_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,B,K,&R,&sigmai->sigmai[i].B,&sigmai->sigmai[i].K,&Ri,m);
        // if(c == s->c){
        if(BIG_comp(c,sigmai->sigmai[i].c)){
            // cout << "sRL revoked! " << endl;
            printf("sRL revoked!\n");
            return -1;
        }
    }
    return 0;
}

void revokerRevokePRL(GPK *gpk, Public_PRL *pPRL, Revoker_SK *sk){
    // G2 wxg2 = gpk->w + revokerPFC->mult(gpk->g2, sk->x);

    G2 wxg2,tmp_G2_1;
    G2_copy(&wxg2,&gpk->w);
    pair_mult_G2(&tmp_G2_1,&gpk->g2,sk->x);
    G2_add(&wxg2,&tmp_G2_1);
    // G2_add(&wxg2,&gpk->w);

    // G1 g1h1fh2y = -(platformPFC->mult(gpk->h1, sk->f) + platformPFC->mult(gpk->h2, y) + gpk->g1);
    G1 g1h1fh2y;
    G1 h1f,h2y;
    pair_mult_G1(&h1f,&gpk->h1,sk->f);
    pair_mult_G1(&h2y,&gpk->h2,sk->y);
    G1_copy(&g1h1fh2y,&gpk->g1);
    G1_add(&g1h1fh2y,&h1f);
    G1_add(&g1h1fh2y,&h2y);

    // G1 *e1[2];
    // G2 *e2[2];
    // e1[0] = &sk->A;
    // e1[1] = &g1h1fh2y;
    // e2[0] = &wxg2;
    // e2[1] = &gpk->g2;
    GT left,right;
    pairing(&left,&wxg2,&sk->A);
    pairing(&right,&gpk->g2,&g1h1fh2y);

    // if (revokerPFC->multi_pairing(2, e2, e1) != 1)
    // {
    //     cout << "Pairing verification failed, aborting.. " << endl;
    //     exit(0);
    // }

    if (!GT_equals(&left,&right))
    {
        printf("Pairing verification failed, aborting.. \n");
        return;
    }

    PRLNode *tmp = (PRLNode*)malloc(sizeof(PRLNode));
    // PRLNode *tmp = new PRLNode();
    // tmp->f = sk->f;
    BIG_copy(tmp->f,sk->f);
    if(pRL->head==NULL){
        pRL->head = tmp;
    }else{
        pRL->tail->next = tmp;
    }
    pRL->tail = tmp;

    setPRL(pPRL);
}
int revokerRevokeSRL(GPK *gpk, Public_PRL *pPRL, Public_SRL *pSRL, char *m, Revoker_Sigma *sigma){
    if(revokerVerify(gpk,m,pPRL,&sigma->sigmai,&sigma->sigma0))return -1;
    BK *tmp = (BK*)malloc(sizeof(BK));
    // BK *tmp = new BK();
    // tmp->B = sigma->sigma0->B;
    // tmp->K = sigma->sigma0->K;
    G1_copy(&tmp->B,&sigma->sigma0.B);
    G1_copy(&tmp->K,&sigma->sigma0.K);
    if(sRL->head==NULL){
        sRL->head = tmp;
    }else{
        sRL->tail->next = tmp;
    }
    sRL->tail = tmp;

    setSRL(pSRL);
    return 0;
}

int revokerVerify(GPK *gpk, char *m, Public_PRL *pPRL, Revoker_Sigmai *sigmai, Revoker_Sigma0 *sigma0)
{
    // 验证sigma0的知识证明
    // G3 R1 = revokerPFC->mult(sigma0->B, sigma0->sf) + revokerPFC->mult(sigma0->K, (-1) * sigma0->c);
    G3 R1,tmp_G3;
    Big tmp_Big;
    pair_mult_G1(&R1, &sigma0->B, sigma0->sf);
    BIG_modneg(tmp_Big, sigma0->c,gpk->p);
    pair_mult_G1(&tmp_G3, &sigma0->K, tmp_Big);
    G1_add(&R1, &tmp_G3);
    // GT R2 = revokerPFC->pairing(revokerPFC->mult(gpk->g2, (-1) * sigma0->sx) + revokerPFC->mult(gpk->w, (-1) * sigma0->c), sigma0->T) * revokerPFC->power(rt2, sigma0->sf) * revokerPFC->power(rt3, sigma0->sb) * revokerPFC->power(rt4, sigma0->sa) * revokerPFC->power(rt1, sigma0->c);
    GT R2,tmp_GT_1, tmp_GT_2,tmp_GT_3,tmp_GT_4;
    G2 tmp_G2_1,tmp_G2_2;
    G1 tmp_G1;
    BIG_modneg(tmp_Big, sigma0->sx,gpk->p);
    pair_mult_G2(&tmp_G2_1, &gpk->g2, tmp_Big);
    BIG_modneg(tmp_Big, sigma0->c,gpk->p);
    pair_mult_G2(&tmp_G2_2, &gpk->w, tmp_Big);
    G2_add(&tmp_G2_1, &tmp_G2_2);
    pairing(&R2,&tmp_G2_1,&sigma0->T);
    pair_power_GT(&tmp_GT_2, &rt2, sigma0->sf);
    pair_power_GT(&tmp_GT_3, &rt3, sigma0->sb);
    pair_power_GT(&tmp_GT_4, &rt4, sigma0->sa);
    pair_power_GT(&tmp_GT_1, &rt1, sigma0->c);
    GT_mul(&R2, &tmp_GT_2);
    GT_mul(&R2, &tmp_GT_3);
    GT_mul(&R2, &tmp_GT_4);
    GT_mul(&R2, &tmp_GT_1);
    // revokerPFC->start_hash();
    // revokerPFC->add_to_hash(gpk->p);
    // revokerPFC->add_to_hash(gpk->g1);
    // revokerPFC->add_to_hash(gpk->g2);
    // revokerPFC->add_to_hash(gpk->g3);
    // revokerPFC->add_to_hash(gpk->h1);
    // revokerPFC->add_to_hash(gpk->h2);
    // revokerPFC->add_to_hash(gpk->w);
    // revokerPFC->add_to_hash(sigma0->B);
    // revokerPFC->add_to_hash(sigma0->K);
    // revokerPFC->add_to_hash(sigma0->T);
    // revokerPFC->add_to_hash(R1);
    // revokerPFC->add_to_hash(R2);
    // revokerPFC->add_to_hash(m);
    // Big c = revokerPFC->finish_hash_to_group();
    Big c;
    hash_sigma_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma0->B,&sigma0->K,&sigma0->T,&R1,&R2,m);


    // if (c != sigma0->c)
    if(BIG_comp(c, sigma0->c))
    {
        // cout << " Revoker verification failed, aborting.. " << endl;
        printf(" Revoker verification failed, aborting.. \n");
        return -2;
    }
//检查pRL和sRL
    if(revokerCheckPRL(pPRL, &sigma0->B, &sigma0->K))return -1;
    if(revokerCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K))return -1;

    // cout << "Revoker verification succeeds! " << endl;
    printf("Revoker verification succeeds! \n");
    return 0;
}

void printPRLNode(PRLNode *pRLNode){
    // cout<<"type: PRLNode"<<endl;
    // cout<<"    f: "<< pRLNode->f << endl;
    // cout<<"        f len: "<< pRLNode->f.len() << endl;
    // cout<<"        f size: "<<sizeof(pRLNode->f)<<endl;
    // cout<<"PRLNode size: "<<sizeof(*pRLNode)<<endl;
    printf("    f--\n   ");
    display_Big(pRLNode->f);
}

void printPRL(PRL *pRL){
    // cout<<"type: PRL"<<endl;
    printf("[pRL]Revoker\n");
    PRLNode *p=pRL->head;
    while (p!=NULL)
    {
        printPRLNode(p);
        p=p->next;  
    }
    // cout<<"PRL size: "<<sizeof(*pRL)<<endl;
}

void printBK(BK *bk){
    // cout<<"type: BK"<<endl;
    // cout<<"    B.g: "<< bk->B.g << endl;
    // cout<<"        B size: "<<sizeof(bk->B)<<endl;
    // cout<<"    K.g: "<< bk->K.g << endl;
    // cout<<"        K size: "<<sizeof(bk->K)<<endl;
    // cout<<"BK size: "<<sizeof(*bk)<<endl;
    printf("    B--\n    ");
    display_G1(&bk->B);
    printf("    K--\n    ");
    display_G1(&bk->K);
}

void printSRL(SRL *sRL){
    // cout<<"type: SRL"<<endl;
    printf("[sRL]Revoker\n");
    BK *p=sRL->head;
    while (p!=NULL)
    {
        printBK(p);
        p=p->next;  
    }
    // cout<<"SRL size: "<<sizeof(*sRL)<<endl;
}

void printRevoker_SK(Revoker_SK *sk){
    // cout<<"type: Revoker_SK"<<endl;
    // cout<<"    A.g: "<< sk->A.g << endl;
    // cout<<"        A size: "<<sizeof(sk->A)<<endl;
    // cout<<"    x: "<< sk->x << endl;
    // cout<<"        x len: "<<sk->x.len()<<endl;
    // cout<<"        x size: "<<sizeof(sk->x)<<endl;
    // cout<<"    y: "<< sk->y << endl;
    // cout<<"        y len: "<<sk->y.len()<<endl;
    // cout<<"        y size: "<<sizeof(sk->y)<<endl;
    // cout<<"    f: "<< sk->f << endl;
    // cout<<"        f len: "<<sk->f.len()<<endl;
    // cout<<"        f size: "<<sizeof(sk->f)<<endl;
    // cout<<"Revoker_SK size: "<<sizeof(*sk)<<endl;
    printf("[sk]RevokerRecieved: \n");
	printf("    A--\n   ");
	display_G1(&sk->A);
	printf("    f--\n   ");
	display_Big(&sk->f);
	printf("    x--\n   ");
	display_Big(&sk->x);
	printf("    y--\n   ");
	display_Big(&sk->y);
}

void printRevoker_BK_SPK(Revoker_BK_SPK *sigmai){
    // cout<<"type: Revoker_BK_SPK"<<endl;
    // cout<<"    B.g: "<< sigmai->B.g << endl;
    // cout<<"        B size: "<<sizeof(sigmai->B)<<endl;
    // cout<<"    K.g: "<< sigmai->K.g << endl;
    // cout<<"        K size: "<<sizeof(sigmai->K)<<endl;
    // cout<<"Revoker_BK_SPK size: "<<sizeof(*sigmai)<<endl;
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

void printRevoker_Sigma0(Revoker_Sigma0 *sigma0){
    // cout<<"type: Revoker_Sigma0"<<endl;
    // cout<<"    B.g: "<< sigma0->B.g << endl;
    // cout<<"        B size: "<<sizeof(sigma0->B)<<endl;
    // cout<<"    K.g: "<< sigma0->K.g << endl;
    // cout<<"        K size: "<<sizeof(sigma0->K)<<endl;
    // cout<<"    T.g: "<< sigma0->T.g << endl;
    // cout<<"        T size: "<<sizeof(sigma0->T)<<endl;
    // cout<<"    c: "<< sigma0->c << endl;
    // cout<<"        c len: "<<sigma0->c.len()<<endl;
    // cout<<"        c size: "<<sizeof(sigma0->c)<<endl;
    // cout<<"    sf: "<< sigma0->sf << endl;
    // cout<<"        sf len: "<<sigma0->sf.len()<<endl;
    // cout<<"        sf size: "<<sizeof(sigma0->sf)<<endl;
    // cout<<"    sx: "<< sigma0->sx << endl;
    // cout<<"        sx len: "<<sigma0->sx.len()<<endl;
    // cout<<"        sx size: "<<sizeof(sigma0->sx)<<endl;
    // cout<<"    sa: "<< sigma0->sa << endl;
    // cout<<"        sa len: "<<sigma0->sa.len()<<endl;
    // cout<<"        sa size: "<<sizeof(sigma0->sa)<<endl;
    // cout<<"    sb: "<< sigma0->sb << endl;
    // cout<<"        sb len: "<<sigma0->sb.len()<<endl;
    // cout<<"        sb size: "<<sizeof(sigma0->sb)<<endl;
    // cout<<"Revoker_Sigma0 size: "<<sizeof(*sigma0)<<endl;
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

void printRevoker_Sigmai(Revoker_Sigmai *sigmai){
    // cout<<"type: Revoker_Sigmai"<<endl;
    printf("    Sigmai\n");
    // cout<<"    cnt: "<< sigmai->cnt << endl;
    for(int i=0;i<sigmai->cnt;i++){
        printRevoker_BK_SPK(sigmai->sigmai+i);
    } 
    // cout<<"Revoker_Sigmai size: "<<sizeof(*sigmai)<<endl;
}

void printRevoker_Sigma(Revoker_Sigma *sigma){
    // cout<<"type: Revoker_Sigma"<<endl;
    printf("[sigma]RevokerRecieved: \n");
    printRevoker_Sigma0(&sigma->sigma0);
    printRevoker_Sigmai(&sigma->sigmai);
    // cout<<"Revoker_Sigma size: "<<sizeof(*sigma)<<endl;
}