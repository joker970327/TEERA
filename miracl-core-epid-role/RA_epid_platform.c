#include "RA_epid_platform.h"

GT pt1,pt2,pt3,pt4;
SK sk;//sk
Big y_1;

// PFC *platformPFC=&pfc;

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
    // CommC *commC = (CommC *)malloc(sizeof(CommC));
    // commC->C = platformPFC->mult(gpk->h1, f) + platformPFC->mult(gpk->h2, y_1);

    // commC->C=h1^f*h2^y_1
    G1 tmp;
    pair_mult_G1(&commC->C,&gpk->h1,sk.f);
    pair_mult_G1(&tmp,&gpk->h2,y_1);
    G1_add(&commC->C,&tmp);
    
    Big rf, ry1;
    G1 PoC;
    random_Big(rf);
    random_Big(ry1);
    // PoC = platformPFC->mult(gpk->h1, rf) + platformPFC->mult(gpk->h2, ry1);
    pair_mult_G1(&PoC,&gpk->h1,rf);
    pair_mult_G1(&tmp,&gpk->h2,ry1);
    G1_add(&PoC,&tmp);
    // 计算c的哈希值，暂时只用一些参数，需要与证明的对应
    // 论文未说明具体哈希值，只说做标准零知识证明
    // platformPFC->start_hash();
    // platformPFC->add_to_hash(gpk->p);
    // platformPFC->add_to_hash(gpk->h1);
    // platformPFC->add_to_hash(gpk->h2);
    // platformPFC->add_to_hash(commC->C);
    // platformPFC->add_to_hash(PoC);
    // c = platformPFC->finish_hash_to_group();

    hash_comm_epid(commC->c, gpk->p, &gpk->g1, &gpk->g2, &gpk->g3, &gpk->h1, &gpk->h2, &gpk->w, &commC->C, &PoC);

    // sk = new SK();
    // sk->f = f;
    // BIG_copy(sk.f,f);

    // commC->sf = (rf + modmult(c, f, gpk->p)) % gpk->p;
    // commC->sy1 = (ry1 + modmult(c, y_1, gpk->p)) % gpk->p;
    // commC->c = c;

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
    // Big y = (y_1 + cre->y2) % gpk->p;
    modadd(sk.y,y_1,cre->y2,gpk->p);
    // pairing验证
    // G2 wxg2 = gpk->w + platformPFC->mult(gpk->g2, cre->x);
    G2 wxg2,tmp_G2_1;
    G2_copy(&wxg2,&gpk->w);
    pair_mult_G2(&tmp_G2_1,&gpk->g2,cre->x);
    G2_add(&wxg2,&tmp_G2_1);
    // G2_add(&wxg2,&gpk->w);

    // G1 g1h1fh2y = -(platformPFC->mult(gpk->h1, sk->f) + platformPFC->mult(gpk->h2, y) + gpk->g1);
    G1 g1h1fh2y;
    G1 h1f,h2y;
    pair_mult_G1(&h1f,&gpk->h1,sk.f);
    pair_mult_G1(&h2y,&gpk->h2,sk.y);
    G1_copy(&g1h1fh2y,&gpk->g1);
    G1_add(&g1h1fh2y,&h1f);
    G1_add(&g1h1fh2y,&h2y);
    // G1_neg(&g1h1fh2y);

    // G1 *e1[2];
    // G2 *e2[2];
    // e1[0] = &cre->A;
    // e1[1] = &g1h1fh2y;
    // e2[0] = &wxg2;
    // e2[1] = &gpk->g2;

    GT left,right;
    pairing(&left,&wxg2,&cre->A);
    pairing(&right,&gpk->g2,&g1h1fh2y);

    // if (platformPFC->multi_pairing(2, e2, e1) != 1)
    // {
    //     cout << "Pairing verification failed, aborting.. " << endl;
    //     return -1;
    // }

    if (!GT_equals(&left,&right))
    {
        printf("Pairing verification failed, aborting.. \n");
        return -1;
    }

    // sk->A = cre->A;
    // sk->x = cre->x;
    // // sk->y = y;

    // pk->A = cre->A;
    // pk->x = cre->x;
    // pk->y = y;

    G1_copy(&sk.A,&cre->A);
    BIG_copy(sk.x,cre->x);
    G1_copy(&pk->A,&cre->A);
    BIG_copy(pk->x,cre->x);
    BIG_copy(pk->y,sk.y);

    return 0;
}

void platformSign(GPK *gpk, char *m, Public_SRL *sRL, Platform_Sigma* sigma)
{
    // G3 B, K, R1;
    // G1 T;
    G3 R1;
    GT R2;
    Big a, b;

    // platformPFC->random(B);
    random_G1(&sigma->sigma0.B);
    // K = platformPFC->mult(B, sk->f);
    pair_mult_G1(&sigma->sigma0.K,&sigma->sigma0.B,sk.f);
    // platformPFC->random(a);
    random_Big(a);
    // b = sk->y + modmult(a, sk->x, gpk->p) % gpk->p;
    modmult(b,a,sk.x,gpk->p);
    modadd(b,sk.y,b,gpk->p);
    // T = sk->A + platformPFC->mult(gpk->h2, a);
    pair_mult_G1(&sigma->sigma0.T,&gpk->h2,a);
    G1_add(&sigma->sigma0.T,&sk.A);

    // 生成sigma0的知识证明
    Big rx, rf, ra, rb;
    // Big sx, sf, sa, sb;
    // platformPFC->random(rx);
    // platformPFC->random(rf);
    // platformPFC->random(ra);
    // platformPFC->random(rb);
    random_Big(rx);
    random_Big(rf);
    random_Big(ra);
    random_Big(rb);

    // R1 = platformPFC->mult(B, rf);
    pair_mult_G1(&R1,&sigma->sigma0.B,rf);

    // R2 = platformPFC->power(platformPFC->pairing(gpk->g2, sk->A), -rx) 
    //    * platformPFC->power(pt2, rf) 
    //    * platformPFC->power(pt3, rb - modmult(a, rx, gpk->p) % gpk->p) 
    //    * platformPFC->power(pt4, ra);
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


    // platformPFC->start_hash();
    // platformPFC->add_to_hash(gpk->p);
    // platformPFC->add_to_hash(gpk->g1);
    // platformPFC->add_to_hash(gpk->g2);
    // platformPFC->add_to_hash(gpk->g3);
    // platformPFC->add_to_hash(gpk->h1);
    // platformPFC->add_to_hash(gpk->h2);
    // platformPFC->add_to_hash(gpk->w);
    // platformPFC->add_to_hash(B);
    // platformPFC->add_to_hash(K);
    // platformPFC->add_to_hash(T);
    // platformPFC->add_to_hash(R1);
    // platformPFC->add_to_hash(R2);
    // platformPFC->add_to_hash(m);
    // c = platformPFC->finish_hash_to_group();
    hash_sigma_epid(sigma->sigma0.c,gpk->p,&gpk->g1,&gpk->g2,&gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma->sigma0.B,&sigma->sigma0.K,&sigma->sigma0.T,&R1,&R2,m);

    // sx = (rx + modmult(c, sk->x, gpk->p)) % gpk->p;
    // sa = (ra + modmult(c, a, gpk->p)) % gpk->p;
    // sb = (rb + modmult(c, b, gpk->p)) % gpk->p;
    // sf = (rf + modmult(c, sk->f, gpk->p)) % gpk->p;

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


    // sigma->sigma0->B = B;
    // sigma->sigma0->K = K;
    // sigma->sigma0->c = c;
    // sigma->sigma0->T = T;
    // sigma->sigma0->sa = sa;
    // sigma->sigma0->sx = sx;
    // sigma->sigma0->sb = sb;
    // sigma->sigma0->sf = sf;

    // G1_copy(&sigma->sigma0.B,&B);
    // G1_copy(&sigma->sigma0.K,&K);
    // BIG_copy(sigma->sigma0.c,c);
    // G1_copy(&sigma->sigma0.T,&T);
    // BIG_copy(sigma->sigma0.sa,sa);
    // BIG_copy(sigma->sigma0.sx,sx);
    // BIG_copy(sigma->sigma0.sb,sb);
    // BIG_copy(sigma->sigma0.sf,sf);


    // 生成sigmai


    // sigmai涉及到不等式进行知识证明
    // 暂时将每个不等式作为一个单独的知识证明，sigma0中已经证明了B=K^f
    // 那么sigmai就证明Ki=Bi^f，但是需要每一个都证明失败
    sigma->sigmai.sigmai = (Platform_BK_SPK *)malloc(sRL->cnt*sizeof(Platform_BK_SPK));
    sigma->sigmai.cnt = sRL->cnt;

    for(int i=0;i<sRL->cnt;i++)
    {
        // s = &(sRL->sRLNode[i]);
        // G3 R = platformPFC->mult(B,rf);
        G3 R;
        pair_mult_G1(&R,&sigma->sigma0.B,rf);
        // G3 Ri = platformPFC->mult(s->B,rf);
        G3 Ri;
        pair_mult_G1(&Ri,&sRL->sRLNode[i].B,rf);
        // platformPFC->start_hash();
        // platformPFC->add_to_hash(gpk->p);
        // platformPFC->add_to_hash(gpk->g1);
        // platformPFC->add_to_hash(gpk->g2);
        // platformPFC->add_to_hash(gpk->g3);
        // platformPFC->add_to_hash(gpk->h1);
        // platformPFC->add_to_hash(gpk->h2);
        // platformPFC->add_to_hash(gpk->w);
        // platformPFC->add_to_hash(B);
        // platformPFC->add_to_hash(K);
        // platformPFC->add_to_hash(R);
        // platformPFC->add_to_hash(s->B);
        // platformPFC->add_to_hash(s->K);
        // platformPFC->add_to_hash(Ri);
        // platformPFC->add_to_hash(m);
        // c = platformPFC->finish_hash_to_group();

        hash_SRLNode_epid(sigma->sigmai.sigmai[i].c,gpk->p,&gpk->g1,&gpk->g2,
            &gpk->g3,&gpk->h1,&gpk->h2,&gpk->w,&sigma->sigma0.B,
            &sigma->sigma0.K,&R,&sRL->sRLNode[i].B,&sRL->sRLNode[i].K,
            &Ri,m);

        // sf = (rf + modmult(c, sk->f, gpk->p))%gpk->p;

        // sigma->sigmai->sigmai[i].B = s->B;
        // sigma->sigmai->sigmai[i].K = s->K;
        // sigma->sigmai->sigmai[i].c = c;
        // sigma->sigmai->sigmai[i].sf = sf;

        G1_copy(&sigma->sigmai.sigmai[i].B,&sRL->sRLNode[i].B);
        G1_copy(&sigma->sigmai.sigmai[i].K,&sRL->sRLNode[i].K);
        // BIG_copy(sigma->sigmai.sigmai[i].c,sigma->sigma0.c);
        BIG_copy(sigma->sigmai.sigmai[i].sf,sigma->sigma0.sf);

    }
}

SK* platformLeakSK_Test(){
    return &sk;
}

void printSK(){
    // cout<<"type: SK"<<endl;
    // cout<<"    A.g: "<<sk->A.g<<endl;
    // cout<<"        A size: "<<sizeof(sk->A)<<endl;
    // cout<<"    f: "<<sk->f<<endl;
    // cout<<"        f len: "<<sk->f.len()<<endl;
    // cout<<"        f size: "<<sizeof(sk->f)<<endl;
    // cout<<"    x: "<<sk->x<<endl;
    // cout<<"        x len: "<<sk->x.len()<<endl;
    // cout<<"        x size: "<<sizeof(sk->x)<<endl;
    // cout<<"    y: "<<sk->y<<endl; 
    // cout<<"        y len: "<<sk->y.len()<<endl;
    // cout<<"        y size: "<<sizeof(sk->y)<<endl;
    // cout<<"SK size: "<<sizeof(*sk)<<endl;
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
    // cout<<"type: Platform_CommC"<<endl;
    // cout<<"    C.g: "<<commC->C.g<<endl;
    // cout<<"        C size: "<<sizeof(commC->C)<<endl;
    // cout<<"    c: "<<commC->c<<endl;
    // cout<<"        c len: "<<commC->c.len()<<endl;
    // cout<<"        c size: "<<sizeof(commC->c)<<endl;
    // cout<<"    sf: "<<commC->sf<<endl;
    // cout<<"        sf len: "<<commC->sf.len()<<endl;
    // cout<<"        sf size: "<<sizeof(commC->sf)<<endl;
    // cout<<"    sy1: "<<commC->sy1<<endl;
    // cout<<"        sy1 len: "<<commC->sy1.len()<<endl;
    // cout<<"        sy1 size: "<<sizeof(commC->sy1)<<endl;
    // cout<<"Platform_CommC size: "<<sizeof(*commC)<<endl;

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
    // cout<<"type: Platform_CRE"<<endl;
    // cout<<"    A.g: "<<cre->A.g<<endl;
    // cout<<"        A size: "<<sizeof(cre->A)<<endl;
    // cout<<"    x: "<<cre->x<<endl;
    // cout<<"        x len: "<<cre->x.len()<<endl;
    // cout<<"        x size: "<<sizeof(cre->x)<<endl;
    // cout<<"    y2: "<<cre->y2<<endl;
    // cout<<"        y2 len: "<<cre->y2.len()<<endl;
    // cout<<"        y2 size: "<<sizeof(cre->y2)<<endl;
    // cout<<"Platform_CRE size: "<<sizeof(*cre)<<endl;

    printf("[cre]PlatformRecieved: \n");
	printf("    A--\n    ");
	display_G1(&cre->A);
	printf("    x--\n    ");
	display_Big(cre->x);
    printf("    y2--\n    ");
    display_Big(cre->y2);
}
void printPlatformBKSPK(Platform_BK_SPK* bk_spk){
    // cout<<"type: Platform_BK_SPK"<<endl;
    // cout<<"    B.g: "<<bk_spk->B.g<<endl;
    // cout<<"        B size: "<<sizeof(bk_spk->B)<<endl;
    // cout<<"    K.g: "<<bk_spk->K.g<<endl;
    // cout<<"        K size: "<<sizeof(bk_spk->K)<<endl;
    // cout<<"    c: "<<bk_spk->c<<endl;
    // cout<<"        c len: "<<bk_spk->c.len()<<endl;
    // cout<<"        c size: "<<sizeof(bk_spk->c)<<endl;
    // cout<<"    sf: "<<bk_spk->sf<<endl;
    // cout<<"        sf len: "<<bk_spk->sf.len()<<endl;
    // cout<<"        sf size: "<<sizeof(bk_spk->sf)<<endl;
    // cout<<"Platform_BK_SPK size: "<<sizeof(*bk_spk)<<endl;

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
    // cout<<"type: Platform_Sigma0"<<endl;
    // cout<<"    B.g: "<<sigma0->B.g<<endl;
    // cout<<"        B size: "<<sizeof(sigma0->B)<<endl;
    // cout<<"    K.g: "<<sigma0->K.g<<endl;
    // cout<<"        K size: "<<sizeof(sigma0->K)<<endl;
    // cout<<"    T.g: "<<sigma0->T.g<<endl;
    // cout<<"        T size: "<<sizeof(sigma0->T)<<endl;
    // cout<<"    c: "<<sigma0->c<<endl;
    // cout<<"        c len: "<<sigma0->c.len()<<endl;
    // cout<<"        c size: "<<sizeof(sigma0->c)<<endl;
    // cout<<"    sf: "<<sigma0->sf<<endl;
    // cout<<"        sf len: "<<sigma0->sf.len()<<endl;
    // cout<<"        sf size: "<<sizeof(sigma0->sf)<<endl;
    // cout<<"    sx: "<<sigma0->sx<<endl;
    // cout<<"        sx len: "<<sigma0->sx.len()<<endl;
    // cout<<"        sx size: "<<sizeof(sigma0->sx)<<endl;
    // cout<<"    sa: "<<sigma0->sa<<endl;
    // cout<<"        sa len: "<<sigma0->sa.len()<<endl;
    // cout<<"        sa size: "<<sizeof(sigma0->sa)<<endl;
    // cout<<"    sb: "<<sigma0->sb<<endl;
    // cout<<"        sb len: "<<sigma0->sb.len()<<endl;
    // cout<<"        sb size: "<<sizeof(sigma0->sb)<<endl;
    // cout<<"Platform_Sigma0 size: "<<sizeof(*sigma0)<<endl;

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
    // cout<<"type: Platform_Sigmai"<<endl;
    // cout<<"    cnt: "<<sigmai->cnt<<endl;
    // for(int i=0;i<sigmai->cnt;i++){
    //     printPlatformBKSPK(sigmai->sigmai+i);
    // }
    // cout<<"Platform_Sigmai size: "<<sizeof(*sigmai)<<endl;

    printf("    Sigmai\n");
    for(int i=0;i<sigmai->cnt;i++){
        printPlatformBKSPK(sigmai->sigmai+i);
    }
}

void printPlatformSigma(Platform_Sigma* sigma){
    // cout<<"type: Platform_Sigma"<<endl;
    // printPlatformSigma0(sigma->sigma0);
    // for(int i=0;i<sigma->sigmai->cnt;i++){
    //     printPlatformSigmai(sigma->sigmai+i);
    // }
    // cout<<"Platform_Sigma size: "<<sizeof(*sigma)<<endl;
    printf("[sigma]PlatformSend: \n");
    printPlatformSigma0(&sigma->sigma0);
    printPlatformSigmai(&sigma->sigmai);
}

void printPPK(PPK *ppk){
    // cout<<"type: PPK"<<endl;
    // cout<<"    A.g: "<<ppk->A.g<<endl;
    // cout<<"        A size: "<<sizeof(ppk->A)<<endl;
    // cout<<"    x: "<<ppk->x<<endl;
    // cout<<"        x len: "<<ppk->x.len()<<endl;
    // cout<<"        x size: "<<sizeof(ppk->x)<<endl;
    // cout<<"    y: "<<ppk->y<<endl;
    // cout<<"        y len: "<<ppk->y.len()<<endl;
    // cout<<"        y size: "<<sizeof(ppk->y)<<endl;
    // cout<<"PPK size: "<<sizeof(*ppk)<<endl;

    printf("[PPK]PlatformSet:\n");
    printf("    A--\n    ");
    display_G1(&ppk->A);
    printf("    x--\n    ");
    display_Big(ppk->x);
    printf("    y--\n    ");
    display_Big(ppk->y);
}