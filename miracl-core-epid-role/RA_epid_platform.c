#include "RA_epid_platform.h"

GT pt1,pt2,pt3,pt4;
SK sk;//sk
Big y_1;

void platformPreCom(GPK* gpk)
{
    initiate();

    pairing(&pt1,&gpk->g2,&gpk->g1);
	pairing(&pt2,&gpk->g2,&gpk->h1);
	pairing(&pt3,&gpk->g2,&gpk->h2);
	pairing(&pt4,&gpk->w,&gpk->h2);
}

void platformJoin_1(GPK *gpk, Platform_CommC* commC)
{
    random_Big(sk.f);
    random_Big(y_1);
    // C的知识证明
    // commC->C=h1^f*h2^y_1
    G1 tmp;
    pair_mult_G1(&commC->C,&gpk->h1,sk.f);
    pair_mult_G1(&tmp,&gpk->h2,y_1);
    G1_add(&commC->C,&tmp);
    
    Big rf, ry1;
    G1 PoC;

    random_Big(rf);
    random_Big(ry1);
    pair_mult_G1(&PoC,&gpk->h1,rf);
    pair_mult_G1(&tmp,&gpk->h2,ry1);
    G1_add(&PoC,&tmp);
    // 计算c的哈希值，暂时只用一些参数，需要与证明的对应
    // 论文未说明具体哈希值，只说做标准零知识证明
 
    hash_comm_epid(commC->c, gpk->p, &gpk->g1, &gpk->g2, &gpk->g3, &gpk->h1, &gpk->h2, &gpk->w, &commC->C, &PoC);

    //sf=rf-c*f
    Big tmp_Big_5;
	modmult(tmp_Big_5,commC->c,sk.f,gpk->p);
    BIG_modneg(tmp_Big_5,tmp_Big_5,gpk->p);
	modadd(commC->sf,rf,tmp_Big_5,gpk->p);

    //sy1=ry1-c*y_1
    modmult(tmp_Big_5,commC->c,y_1,gpk->p);
    BIG_modneg(tmp_Big_5,tmp_Big_5,gpk->p);
    modadd(commC->sy1,ry1,tmp_Big_5,gpk->p);
}

int platformJoin_3(GPK *gpk, Platform_CRE *cre, PPK *pk)
{
    modadd(sk.y,y_1,cre->y2,gpk->p);
    // pairing验证
    G2 wxg2,tmp_G2_1;
    G2_copy(&wxg2,&gpk->w);
    pair_mult_G2(&tmp_G2_1,&gpk->g2,cre->x);
    G2_add(&wxg2,&tmp_G2_1);

    G1 g1h1fh2y;
    G1 h1f,h2y;
    pair_mult_G1(&h1f,&gpk->h1,sk.f);
    pair_mult_G1(&h2y,&gpk->h2,sk.y);
    G1_copy(&g1h1fh2y,&gpk->g1);
    G1_add(&g1h1fh2y,&h1f);
    G1_add(&g1h1fh2y,&h2y);

    GT left,right;
    pairing(&left,&wxg2,&cre->A);
    pairing(&right,&gpk->g2,&g1h1fh2y);

    if (!GT_equals(&left,&right))
    {
        printf("Pairing verification failed, aborting.. \n");
        return -1;
    }

    G1_copy(&sk.A,&cre->A);
    BIG_copy(sk.x,cre->x);
    G1_copy(&pk->A,&cre->A);
    BIG_copy(pk->x,cre->x);
    BIG_copy(pk->y,sk.y);

    return 0;
}

void platformSign(GPK *gpk, char *m, Public_SRL *sRL, Platform_Sigma* sigma)
{

    G3 R1;
    GT R2;
    Big a, b;

    random_G1(&sigma->sigma0.B);
    pair_mult_G1(&sigma->sigma0.K,&sigma->sigma0.B,sk.f);
    random_Big(a);
    modmult(b,a,sk.x,gpk->p);
    modadd(b,sk.y,b,gpk->p);
    pair_mult_G1(&sigma->sigma0.T,&gpk->h2,a);
    G1_add(&sigma->sigma0.T,&sk.A);

    // 生成sigma0的知识证明
    Big rx, rf, ra, rb;

    random_Big(rx);
    random_Big(rf);
    random_Big(ra);
    random_Big(rb);

    pair_mult_G1(&R1,&sigma->sigma0.B,rf);

    Big tmp_Big;
    GT tmp_GT_2,tmp_GT_3,tmp_GT_4;

    pairing(&R2,&gpk->g2,&sk.A);
    BIG_modneg(tmp_Big,rx,gpk->p);
    pair_power_GT(&R2,&R2,tmp_Big);
    pair_power_GT(&tmp_GT_2,&pt2,rf);
    modmult(tmp_Big,a,rx,gpk->p);
    BIG_modneg(tmp_Big,tmp_Big,gpk->p);
    modadd(tmp_Big,tmp_Big,rb,gpk->p);
    pair_power_GT(&tmp_GT_3,&pt3,tmp_Big);
    pair_power_GT(&tmp_GT_4,&pt4,ra);
    GT_mul(&R2,&tmp_GT_2);
    GT_mul(&R2,&tmp_GT_3);
    GT_mul(&R2,&tmp_GT_4);

    hash_sigma_epid(sigma->sigma0.c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma->sigma0.B,&sigma->sigma0.K,&sigma->sigma0.T,&R1,&R2,m);

    Big tmp_Big_6;
	modmult(tmp_Big_6,sigma->sigma0.c,sk.x,gpk->p);
	modadd(sigma->sigma0.sx,rx,tmp_Big_6,gpk->p);

	// sa = (c*a mod p) + ra mod p
	modmult(tmp_Big_6,sigma->sigma0.c,a,gpk->p);
	modadd(sigma->sigma0.sa,ra,tmp_Big_6,gpk->p);

	// sb = (c*b mod p) + rb mod p
	modmult(tmp_Big_6,sigma->sigma0.c,b,gpk->p);
	modadd(sigma->sigma0.sb,rb,tmp_Big_6,gpk->p);

    modmult(tmp_Big_6,sigma->sigma0.c,sk.f,gpk->p);
    modadd(sigma->sigma0.sf,rf,tmp_Big_6,gpk->p);


    // 生成sigmai


    // sigmai涉及到不等式进行知识证明
    // 暂时将每个不等式作为一个单独的知识证明，sigma0中已经证明了B=K^f
    // 那么sigmai就证明Ki=Bi^f，但是需要每一个都证明失败
    sigma->sigmai.sigmai = (Platform_BK_SPK *)malloc(sRL->cnt*sizeof(Platform_BK_SPK));
    sigma->sigmai.cnt = sRL->cnt;

    for(int i=0;i<sRL->cnt;i++)
    {
        G3 Ri;
        pair_mult_G1(&Ri,&sRL->sRLNode[i].B,rf);

        hash_SRLNode_epid(sigma->sigmai.sigmai[i].c,gpk->p,&gpk->g1,&gpk->g2,
            &gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma->sigma0.B,
            &sigma->sigma0.K,&sRL->sRLNode[i].B,&sRL->sRLNode[i].K,
            &Ri,m);

        G1_copy(&sigma->sigmai.sigmai[i].B,&sRL->sRLNode[i].B);
        G1_copy(&sigma->sigmai.sigmai[i].K,&sRL->sRLNode[i].K);

        modmult(tmp_Big,sk.f,sigma->sigmai.sigmai[i].c,gpk->p);
        modadd(sigma->sigmai.sigmai[i].sf,rf,tmp_Big,gpk->p);
        // BIG_copy(sigma->sigmai.sigmai[i].sf,sigma->sigma0.sf);

    }
}

SK* platformLeakSK_Test(){
    return &sk;
}

void printSK(){
    printf("[sk]PlatformSet: \n");
	printf("    A--\n    ");
	display_G1(&sk.A);
	printf("    f--\n    ");
	display_Big(sk.f);
	printf("    x--\n    ");
	display_Big(sk.x);
	printf("    y--\n    ");
	display_Big(sk.y);
}
void printPlatformCommC(Platform_CommC* commC){
    printf("[comm]PlatformSend: \n");
	printf("    C--\n    ");
	display_G1(&commC->C);
	printf("    c--\n    ");
	display_Big(commC->c);
	printf("    sf--\n    ");
	display_Big(commC->sf);
	printf("    sy1--\n    ");
	display_Big(commC->sy1);
}
void printPlatformCRE(Platform_CRE* cre){
    printf("[cre]PlatformRecieved: \n");
	printf("    A--\n    ");
	display_G1(&cre->A);
	printf("    x--\n    ");
	display_Big(cre->x);
    printf("    y2--\n    ");
    display_Big(cre->y2);
}
void printPlatformBKSPK(Platform_BK_SPK* bk_spk){
    printf("        SigmaiNode\n");
    printf("            B--\n           ");
    display_G1(&bk_spk->B);
    printf("            K--\n           ");
    display_G1(&bk_spk->K);
    printf("            c--\n           ");
    display_Big(bk_spk->c);
    printf("            sf--\n           ");
    display_Big(bk_spk->sf);
}

void printPlatformSigma0(Platform_Sigma0* sigma0){
    printf("    Sigma0\n");
    printf("        B--\n        ");
    display_G1(&sigma0->B); 
    printf("        K--\n        ");
    display_G1(&sigma0->K); 
    printf("        T--\n        ");
    display_G1(&sigma0->T); 
    printf("        c--\n        ");
    display_Big(sigma0->c); 
    printf("        sf--\n        ");
    display_Big(sigma0->sf); 
    printf("        sx--\n        ");
    display_Big(sigma0->sx); 
    printf("        sa--\n        ");
    display_Big(sigma0->sa); 
    printf("        sb--\n        ");
    display_Big(sigma0->sb);
}

void printPlatformSigmai(Platform_Sigmai* sigmai){
    printf("    Sigmai\n");
    for(int i=0;i<sigmai->cnt;i++){
        printPlatformBKSPK(&sigmai->sigmai[i]);
    }
}

void printPlatformSigma(Platform_Sigma* sigma){
    printf("[sigma]PlatformSend: \n");
    printPlatformSigma0(&sigma->sigma0);
    printPlatformSigmai(&sigma->sigmai);
}

void printPPK(PPK *ppk){
    printf("[PPK]PlatformSet:\n");
    printf("    A--\n    ");
    display_G1(&ppk->A);
    printf("    x--\n    ");
    display_Big(ppk->x);
    printf("    y--\n    ");
    display_Big(ppk->y);
}