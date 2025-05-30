#include "epid_revokeManager.h"

GT rt1,rt2,rt3,rt4;
SRL *sRL;
PRL *pRL;

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
    pPRL->f = NULL;
    pPRL->f = (Big*)malloc(c*sizeof(Big));
    for(int i=0;i<c;i++){
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
    pSRL->sRLNode = NULL;
    pSRL->sRLNode = (Public_SRLNode*)malloc(c*sizeof(Public_SRLNode));
    for(int i=0;i<c;i++){
        BIG_copy(&pSRL->sRLNode[i].B,&q->B);
        BIG_copy(&pSRL->sRLNode[i].K,&q->K);
        q = q->next;
    }
    pSRL->cnt = c;
}

void revokeManagerPreCom(GPK *gpk, Public_PRL *pPRL, Public_SRL *pSRL)
{
    pRL = (PRL*)malloc(sizeof(PRL));
    sRL = (SRL*)malloc(sizeof(SRL));

    pairing(&rt1,&gpk->g2,&gpk->g1);
	pairing(&rt2,&gpk->g2,&gpk->h1);
	pairing(&rt3,&gpk->g2,&gpk->h2);
	pairing(&rt4,&gpk->w,&gpk->h2);

    setPRL(pPRL);
    setSRL(pSRL);
}

int revokeManagerCheckPRL(Public_PRL *pRL, G3 *B, G3 *K){
    for(int i=0;i<pRL->cnt;i++){
        G1 K1;
        pair_mult_G1(&K1, B, pRL->f[i]);
        if(G1_equals(&K1,K)){
            printf("pRL revoked!\n");
            return -1;
        }
    }
    return 0;
}

int revokeManagerCheckSRL(GPK *gpk, char *m, Revoker_Sigmai *sigmai, G3 *B, G3 *K){
    for(int i=0;i<sigmai->cnt;i++){
        G3 Ri,tmp_G3;
        Big tmp_Big;
        pair_mult_G1(&Ri, &sigmai->sigmai[i].B, &sigmai->sigmai[i].sf);
        BIG_modneg(tmp_Big, sigmai->sigmai[i].c,gpk->p);
        pair_mult_G1(&tmp_G3,&sigmai->sigmai[i].K,tmp_Big);
        G1_add(&Ri, &tmp_G3);

        Big c;
        hash_SRLNode_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,B,K,&sigmai->sigmai[i].B,&sigmai->sigmai[i].K,&Ri,m);
        if(BIG_comp(c,sigmai->sigmai[i].c)){
            printf("sRL revoked!\n");
            return -1;
        }
    }
    return 0;
}

void revokeManagerRevokePRL(GPK *gpk, Public_PRL *pPRL, Revoker_SK *sk){
    G2 wxg2,tmp_G2_1;
    G2_copy(&wxg2,&gpk->w);
    pair_mult_G2(&tmp_G2_1,&gpk->g2,sk->x);
    G2_add(&wxg2,&tmp_G2_1);

    G1 g1h1fh2y;
    G1 h1f,h2y;
    pair_mult_G1(&h1f,&gpk->h1,sk->f);
    pair_mult_G1(&h2y,&gpk->h2,sk->y);
    G1_copy(&g1h1fh2y,&gpk->g1);
    G1_add(&g1h1fh2y,&h1f);
    G1_add(&g1h1fh2y,&h2y);

    GT left,right;
    pairing(&left,&wxg2,&sk->A);
    pairing(&right,&gpk->g2,&g1h1fh2y);

    if (!GT_equals(&left,&right))
    {
        printf("Pairing verification failed, aborting.. \n");
        return;
    }

    PRLNode *tmp = (PRLNode*)malloc(sizeof(PRLNode));

    BIG_copy(tmp->f,sk->f);
    if(pRL->head==NULL){
        pRL->head = tmp;
    }else{
        pRL->tail->next = tmp;
    }
    pRL->tail = tmp;

    setPRL(pPRL);
}
int revokeManagerRevokeSRL(GPK *gpk, Public_PRL *pPRL, Public_SRL *pSRL, char *m, Revoker_Sigma *sigma){
    if(revokeManagerVerify(gpk,m,pPRL,&sigma->sigmai,&sigma->sigma0))return -1;
    BK *tmp = (BK*)malloc(sizeof(BK));

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

int revokeManagerVerify(GPK *gpk, char *m, Public_PRL *pPRL, Revoker_Sigmai *sigmai, Revoker_Sigma0 *sigma0)
{
    G3 R1,tmp_G3;
    Big tmp_Big;
    pair_mult_G1(&R1, &sigma0->B, sigma0->sf);
    BIG_modneg(tmp_Big, sigma0->c,gpk->p);
    pair_mult_G1(&tmp_G3, &sigma0->K, tmp_Big);
    G1_add(&R1, &tmp_G3);

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

    Big c;
    hash_sigma_epid(c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma0->B,&sigma0->K,&sigma0->T,&R1,&R2,m);


    if(BIG_comp(c, sigma0->c))
    {
        printf(" Revoker verification failed, aborting.. \n");
        return -2;
    }
//检查pRL和sRL
    if(revokeManagerCheckPRL(pPRL, &sigma0->B, &sigma0->K))return -1;
    if(revokeManagerCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K))return -1;

    printf("Revoker verification succeeds! \n");
    return 0;
}

void printPRLNode(PRLNode *pRLNode){
    printf("    f--\n   ");
    display_Big(pRLNode->f);
}

void printPRL(PRL *pRL){
    printf("[pRL]Revoker\n");
    PRLNode *p=pRL->head;
    while (p!=NULL)
    {
        printPRLNode(p);
        p=p->next;  
    }
}

void printBK(BK *bk){
    printf("    B--\n    ");
    display_G1(&bk->B);
    printf("    K--\n    ");
    display_G1(&bk->K);
}

void printSRL(SRL *sRL){
    printf("[sRL]Revoker\n");
    BK *p=sRL->head;
    while (p!=NULL)
    {
        printBK(p);
        p=p->next;  
    }
}

void printRevoker_SK(Revoker_SK *sk){
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
    printf("    Sigmai\n");
    for(int i=0;i<sigmai->cnt;i++){
        printRevoker_BK_SPK(sigmai->sigmai+i);
    } 
}

void printRevoker_Sigma(Revoker_Sigma *sigma){
    printf("[sigma]RevokerRecieved: \n");
    printRevoker_Sigma0(&sigma->sigma0);
    printRevoker_Sigmai(&sigma->sigmai);
}
