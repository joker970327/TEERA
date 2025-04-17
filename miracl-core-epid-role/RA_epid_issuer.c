#include "RA_epid_issuer.h"

Big isk;
// PFC *issuerPFC= &pfc;


void issuerSetup(GPK *gpk){
    // issuerPFC = PFC(AES_SECURITY);

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
    // BIG_fromBytes(gpk->p,"00000000000000000000000000000001002001800c00b809c04401c81698b381de05f095a120d3973b2099ebfebc0001");
    // octet g1={97,97,"0444aae3e6d80c35e2bc85fcdd493007d1899769a33767f30d062d8db69a8ff385155e8820a4aafafd574fc0642befaf6e0f1c29c145d2354e40a7959e8609bd4b7ca498518496f5ef753209067ab916e466e6d73ec34db564a44d565b367a9ea1"};
    // ECP_BLS12383_fromOctet(&gpk->g1,&g1);
    // octet h1={97,97,"0423336676205d5b2a667e47d492cb87739f9769bc3615f6f521d8dc0aa5f317287ed4224c8cd90e45917e72aeac9c256b4fadabe5f83031bde6906a72ebbe2c7831c9f3dc3d9ab5ecb1444857ecb916f52c34a2ee02ae2ee408e0c930d2256303"};
    // ECP_BLS12383_fromOctet(&gpk->h1,&h1);
    // octet h2={97,97,"041a2be91fd3c56ad27fa7a2892c19fc3725f819f114f31d0ff9ec9ef4e392e48c7a6eeea4ba47ba904c50109bba5173262ec89cb9ee61790e85a036399f74a96079373989eeb22ffe004e2bac9d8facc5def230e43f0a7766f5c8a4fadd6cb26b"};
    // ECP_BLS12383_fromOctet(&gpk->h2,&h2);
    // octet g2={193,193,"040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014f422def420e46580a2b1e8df0e89756abcc902714eb9e69f8360f274a05dfb4ca005306435905e1ec727c3b724d1ec820e5247dd2cd8c6b24ee7ba7d15a7ae001ce0d446b3efa8f7af0b2f449f7bc98b0143cb0de6224863ad846437f479093000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    // ECP2_BLS12383_fromOctet(&gpk->g2,&g2);
    // octet w={193,193,"042ccda449f682cc2e8426ebe6f50c20423399cbd31229839b833edefa871a493a83bcf964cb16034236d9bfaecd02a4b4210f87733231d0e4208db4d09dce0ea8a8ef9413acfdc9b4e8ffd53b04e4dc33f87f03f24e4ed05d4a09a44395670db8197c0911476fbb9881ab18417528f7560e474bc272f8c69079558574470283bfca7a6b4e0b758e21c1910117118455a40c94599660b09c9fad7b1d6bea07f9750b6a1ac2beba9ed2d116af71623a0a6995ba60cff98188868ced300e88979ac2"};
    // ECP2_BLS12383_fromOctet(&gpk->w,&w);
    // octet g3={97,97,"042971cad629419642238c274366533dbdcdfc5f328be089a0a02c1d8bce18d6c0c14ef44e18aacba3ce7b2fd6e258e4c607975f168996c57524f82fc987513d5fe512ac6c282cb81bb318fdfe462f99e6c9377549c8fa22984636c8dd3b3f0ed1"};

    // issuerPFC->random(gpk->g1);
    // issuerPFC->random(gpk->g2);
    // issuerPFC->random(gpk->g3);
    // issuerPFC->random(isk);
    // issuerPFC->random(gpk->h1);
    // issuerPFC->random(gpk->h2);
    // gpk->w=issuerPFC->mult(gpk->g2, isk);

    // issuerPFC->precomp_for_mult(gpk->g1);
    // issuerPFC->precomp_for_mult(gpk->g2);
    // issuerPFC->precomp_for_mult(gpk->g3);
    // issuerPFC->precomp_for_mult(gpk->h1);
    // issuerPFC->precomp_for_mult(gpk->h2);
    // issuerPFC->precomp_for_mult(gpk->w);
    // issuerPFC->precomp_for_pairing(gpk->g2);
}

void issuerJoin_2(GPK *gpk, Issuer_CommC *commC, Issuer_CRE* cre){
    //CRE *cre = (CRE*)malloc(sizeof(CRE));
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
        // exit(1);
        return;
    }


    // cre->A = issuerPFC->mult(gpk->g1+commC->C+issuerPFC->mult(gpk->h2, cre->y2),inverse(cre->x+isk,gpk->p));
}

void printIssuer_CommC(Issuer_CommC *commC){
    // cout<<"type: Issuer_CommC"<<endl;
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
    // cout<<"Issuer_CommC size: "<<sizeof(*commC)<<endl;
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
    // cout<<"type: Issuer_CRE"<<endl;
    // cout<<"    A.g: "<<cre->A.g<<endl;
    // cout<<"        A size: "<<sizeof(cre->A)<<endl;
    // cout<<"    x: "<<cre->x<<endl;
    // cout<<"        x len: "<<cre->x.len()<<endl;
    // cout<<"        x size: "<<sizeof(cre->x)<<endl;
    // cout<<"    y2: "<<cre->y2<<endl;
    // cout<<"        y2 len: "<<cre->y2.len()<<endl;
    // cout<<"        y2 size: "<<sizeof(cre->y2)<<endl;
    // cout<<"Issuer_CRE size: "<<sizeof(*cre)<<endl;

    printf("[cre]IssuerSend: \n");
	printf("    A--\n   ");
	display_G1(&cre->A);
	printf("    x--\n   ");
	display_Big(cre->x);
    printf("    y2--\n  ");
    display_Big(cre->y2);
}

void printGPK(GPK *gpk){
    // cout<<"type: GPK"<<endl;
    // cout<<"    p: "<<gpk->p<<endl;
    // cout<<"        p len: "<<gpk->p.len()<<endl;
    // cout<<"        p size: "<<sizeof(gpk->p)<<endl;
    // cout<<"    g1.g: "<<gpk->g1.g<<endl;
    // cout<<"        g1 size: "<<sizeof(gpk->g1)<<endl;
    // cout<<"    h1.g: "<<gpk->h1.g<<endl;
    // cout<<"        h1 size: "<<sizeof(gpk->h1)<<endl;
    // cout<<"    h2.g: "<<gpk->h2.g<<endl;
    // cout<<"        h2 size: "<<sizeof(gpk->h2)<<endl;
    // cout<<"    g2.g: "<<gpk->g2.g<<endl;
    // cout<<"        g2 size: "<<sizeof(gpk->g2)<<endl;
    // cout<<"    w.g: "<<gpk->w.g<<endl;
    // cout<<"        w size: "<<sizeof(gpk->w)<<endl;
    // cout<<"    g3.g: "<<gpk->g3.g<<endl;
    // cout<<"        g3 size: "<<sizeof(gpk->g3)<<endl;
    // cout<<"GPK size: "<<sizeof(*gpk)<<endl;

    // cout<<"p.len(): "<<gpk->p.len()<<endl;
    // cout<<"length(p): "<<length(gpk->p)<<endl;
    // cout<<"p.len() * sizeof(mr_small): "<<gpk->p.len() * sizeof(mr_small)<<"bytes"<<endl;
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