// #include <iostream>
// #include <ctime>

#include "RA_epid_type.h"
#include "RA_epid_issuer.h"
#include "RA_epid_platform.h"
#include "RA_epid_revoker.h"
#include "RA_epid_verifier.h"

// PFC pfc(AES_SECURITY);

void failTest_1(){
    // cout << "【fail-test 1】: change message" << endl;
    printf("【fail-test 1】: change message\n");
    // GPK *gpk = new GPK(); 
    // PPK *ppk = new PPK();

    // Public_PRL *pRL = new Public_PRL();
    // Public_SRL *sRL = new Public_SRL();


    // printf("Setup..\n");
    // issuerSetup(gpk);
    // platformPreCom();
    // verifierPreCom();
    // revokerPreCom(pRL,sRL);
// Setup
    GPK gpk;
    PPK ppk;
    Public_PRL *pRL = (Public_PRL*)malloc(sizeof(Public_PRL));
    Public_SRL *sRL = (Public_SRL*)malloc(sizeof(Public_SRL));

    printf("Setup..\n");
    issuerSetup(&gpk);
    platformPreCom(&gpk);
    verifierPreCom(&gpk);
    revokerPreCom(&gpk, pRL,sRL);

    printGPK(&gpk);

    if(ECP_BLS12383_isinf(&gpk.g1))printf("g1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h1))printf("h1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h2))printf("h2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.g2))printf("g2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.w))printf("w is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.g3))printf("g3 is infinity\n");

// Join
    // cout << "Join.." << endl;
    printf("Join..\n");
    // Platform_CommC *platformCommC = new Platform_CommC();
    // Issuer_CommC *issuerCommC;

    // Issuer_CRE *issuerCre = new Issuer_CRE();
    // Platform_CRE *platformCre;

    // // platform 生成 platformCommC
    // platformJoin_1(gpk,platformCommC);
    // // platform 发送 platformCommC 给 issuer
    // // issuer 用 IssuerCommC 接收
    // issuerCommC = (Issuer_CommC*)platformCommC;

    // // issuer 生成 Issuer_CRE
    // issuerJoin_2(gpk, issuerCommC, issuerCre);
    // // issuer 发送 issuerCre 给 platform
    // // platform 用 platformCre 接收
    // platformCre = (Platform_CRE*)issuerCre;

    // // 平台生成公私钥
    // if(platformJoin_3(gpk, platformCre, ppk)) exit(0);
    Platform_CommC platformCommC;
    platformJoin_1(&gpk,&platformCommC);
    // platform 发送 platformCommC 给 issuer
    // issuer 用 IssuerCommC 接收
    Issuer_CommC issuerCommC;
    G1_copy(&issuerCommC.C,&platformCommC.C);
    BIG_copy(issuerCommC.c,platformCommC.c);
    BIG_copy(issuerCommC.sf,platformCommC.sf);
    BIG_copy(issuerCommC.sy1,platformCommC.sy1);
    printPlatformCommC(&platformCommC);

    // issuer 生成 Issuer_CRE
    Issuer_CRE issuerCre;
    issuerJoin_2(&gpk, &issuerCommC, &issuerCre);
    // issuer 发送 issuerCre 给 platform
    // platform 用 platformCre 接收
    Platform_CRE platformCre;
    // &platformCre = (Platform_CRE*)&issuerCre;
    G1_copy(&platformCre.A,&issuerCre.A);
    BIG_copy(platformCre.x,issuerCre.x);
    BIG_copy(platformCre.y2,issuerCre.y2);

    printIssuer_CRE(&issuerCre);

    // 平台生成公私钥
    if(platformJoin_3(&gpk, &platformCre, &ppk)) exit(0);
    printPPK(&ppk);
    printSK();
// change message.. 
// Sign
    // cout << "Sign.." << endl;
    // printf("Sign..\n");
    // char m[] = "Test message to be signed";

    // Platform_Sigma *platformSigma = new Platform_Sigma();
    // platformSigma->sigma0 = new Platform_Sigma0();
    // platformSigma->sigmai = new Platform_Sigmai();
    // platformSigma->sigmai->cnt = sRL->cnt;
    // platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    // platformSign(gpk, m, sRL, platformSigma);

    printf("Sign..\n");
    char m[] = "Test message to be signed";
    Platform_Sigma platformSigma;

    platformSign(&gpk, m, sRL, &platformSigma);

    printPlatformSigma(&platformSigma);

    // TODO：传输格式要注意做适配和更改
    // platform 发送 platformSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigma;
    G1_copy(&verifierSigma.sigma0.B,&platformSigma.sigma0.B);
    BIG_copy(verifierSigma.sigma0.c,platformSigma.sigma0.c);
    BIG_copy(verifierSigma.sigma0.sf,platformSigma.sigma0.sf);
    G1_copy(&verifierSigma.sigma0.T,&platformSigma.sigma0.T);
    BIG_copy(verifierSigma.sigma0.sx,platformSigma.sigma0.sx);
    BIG_copy(verifierSigma.sigma0.sa,platformSigma.sigma0.sa);
    BIG_copy(verifierSigma.sigma0.sb,platformSigma.sigma0.sb);
    G1_copy(&verifierSigma.sigma0.K,&platformSigma.sigma0.K);
    verifierSigma.sigmai.cnt = platformSigma.sigmai.cnt;
    verifierSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*platformSigma.sigmai.cnt);
    for(int i=0;i<platformSigma.sigmai.cnt;i++){
        G1_copy(&verifierSigma.sigmai.sigmai[i].B,&platformSigma.sigmai.sigmai[i].B);
        G1_copy(&verifierSigma.sigmai.sigmai[i].K,&platformSigma.sigmai.sigmai[i].K);
        BIG_copy(verifierSigma.sigmai.sigmai[i].c,platformSigma.sigmai.sigmai[i].c);
        BIG_copy(verifierSigma.sigmai.sigmai[i].sf,platformSigma.sigmai.sigmai[i].sf);
    }

    // cout << "m: \"" << m <<"\"";
    printf("m: \"%s\"",m);
    m[0] = 't';
    // cout<<" is changed into: \""<<m<<"\""<<endl;
    printf(" is changed into: \"%s\"\n",m);

// Verify
    // cout << "Verify.." << endl;
    // Verifier_Sigma *verifierSigma = (Verifier_Sigma*)platformSigma;
    // verifierVerify(gpk, m, pRL, verifierSigma->sigmai, verifierSigma->sigma0);

    printf("Verify..\n");
    verifierVerify(&gpk, m, pRL, &verifierSigma.sigmai, &verifierSigma.sigma0);
}

void failTest_2(){
    // cout << "【fail-test 2】: revoke in sRL" << endl;
    printf("【fail-test 2】: revoke in sRL\n");
    // GPK *gpk = new GPK(); 
    // PPK *ppk = new PPK();

    // Public_PRL *pRL = new Public_PRL();
    // Public_SRL *sRL = new Public_SRL();


    // printf("Setup..\n");
    // issuerSetup(gpk);
    // platformPreCom();
    // verifierPreCom();
    // revokerPreCom(pRL,sRL);
    GPK gpk;
    PPK ppk;
    Public_PRL *pRL = (Public_PRL*)malloc(sizeof(Public_PRL));
    Public_SRL *sRL = (Public_SRL*)malloc(sizeof(Public_SRL));

    printf("Setup..\n");
    issuerSetup(&gpk);
    platformPreCom(&gpk);
    verifierPreCom(&gpk);
    revokerPreCom(&gpk, pRL,sRL);

    printGPK(&gpk);

    if(ECP_BLS12383_isinf(&gpk.g1))printf("g1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h1))printf("h1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h2))printf("h2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.g2))printf("g2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.w))printf("w is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.g3))printf("g3 is infinity\n");

// Join
    // cout << "Join.." << endl;
    printf("Join..\n");
    // Platform_CommC *platformCommC = new Platform_CommC();
    // Issuer_CommC *issuerCommC;

    // Issuer_CRE *issuerCre = new Issuer_CRE();
    // Platform_CRE *platformCre;

    // // platform 生成 platformCommC
    // platformJoin_1(gpk,platformCommC);
    // // platform 发送 platformCommC 给 issuer
    // // issuer 用 IssuerCommC 接收
    // issuerCommC = (Issuer_CommC*)platformCommC;

    // // issuer 生成 Issuer_CRE
    // issuerJoin_2(gpk, issuerCommC, issuerCre);
    // // issuer 发送 issuerCre 给 platform
    // // platform 用 platformCre 接收
    // platformCre = (Platform_CRE*)issuerCre;

    // // 平台生成公私钥
    // if(platformJoin_3(gpk, platformCre, ppk)) exit(0);

    Platform_CommC platformCommC;
    platformJoin_1(&gpk,&platformCommC);
    // platform 发送 platformCommC 给 issuer
    // issuer 用 IssuerCommC 接收
    Issuer_CommC issuerCommC;
    G1_copy(&issuerCommC.C,&platformCommC.C);
    BIG_copy(issuerCommC.c,platformCommC.c);
    BIG_copy(issuerCommC.sf,platformCommC.sf);
    BIG_copy(issuerCommC.sy1,platformCommC.sy1);
    printPlatformCommC(&platformCommC);

    // issuer 生成 Issuer_CRE
    Issuer_CRE issuerCre;
    issuerJoin_2(&gpk, &issuerCommC, &issuerCre);
    // issuer 发送 issuerCre 给 platform
    // platform 用 platformCre 接收
    Platform_CRE platformCre;
    // &platformCre = (Platform_CRE*)&issuerCre;
    G1_copy(&platformCre.A,&issuerCre.A);
    BIG_copy(platformCre.x,issuerCre.x);
    BIG_copy(platformCre.y2,issuerCre.y2);

    printIssuer_CRE(&issuerCre);

    // 平台生成公私钥
    if(platformJoin_3(&gpk, &platformCre, &ppk)) exit(0);
    printPPK(&ppk);
    printSK();
// revoke in sRL
// Sign
    // cout << "Original Sign.." << endl;
    // char m[] = "Test message to be signed";

    // Platform_Sigma *platformSigma = new Platform_Sigma();
    // platformSigma->sigma0 = new Platform_Sigma0();
    // platformSigma->sigmai = new Platform_Sigmai();
    // platformSigma->sigmai->cnt = sRL->cnt;
    // platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    // platformSign(gpk, m, sRL, platformSigma);

    printf("Original Sign..\n");
    char m[] = "Test message to be signed";
    Platform_Sigma platformSigma;

    platformSign(&gpk, m, sRL, &platformSigma);

    printPlatformSigma(&platformSigma);

    // TODO：传输格式要注意做适配和更改
    // platform 发送 platformSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigma;
    G1_copy(&verifierSigma.sigma0.B,&platformSigma.sigma0.B);
    BIG_copy(verifierSigma.sigma0.c,platformSigma.sigma0.c);
    BIG_copy(verifierSigma.sigma0.sf,platformSigma.sigma0.sf);
    G1_copy(&verifierSigma.sigma0.T,&platformSigma.sigma0.T);
    BIG_copy(verifierSigma.sigma0.sx,platformSigma.sigma0.sx);
    BIG_copy(verifierSigma.sigma0.sa,platformSigma.sigma0.sa);
    BIG_copy(verifierSigma.sigma0.sb,platformSigma.sigma0.sb);
    G1_copy(&verifierSigma.sigma0.K,&platformSigma.sigma0.K);
    verifierSigma.sigmai.cnt = platformSigma.sigmai.cnt;
    verifierSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*platformSigma.sigmai.cnt);
    for(int i=0;i<platformSigma.sigmai.cnt;i++){
        G1_copy(&verifierSigma.sigmai.sigmai[i].B,&platformSigma.sigmai.sigmai[i].B);
        G1_copy(&verifierSigma.sigmai.sigmai[i].K,&platformSigma.sigmai.sigmai[i].K);
        BIG_copy(verifierSigma.sigmai.sigmai[i].c,platformSigma.sigmai.sigmai[i].c);
        BIG_copy(verifierSigma.sigmai.sigmai[i].sf,platformSigma.sigmai.sigmai[i].sf);
    }

// Verify
    // cout << "Original Verify.." << endl;
    // Verifier_Sigma *verifierSigma = (Verifier_Sigma*)platformSigma;
    // verifierVerify(gpk, m, pRL, verifierSigma->sigmai, verifierSigma->sigma0);

// sRL 撤销
    // cout << "revoke in sRL.. "<<endl;
    // Revoker_Sigma *revokerSigma = (Revoker_Sigma*)platformSigma;
    // revokerRevokeSRL(gpk,pRL,sRL,m,revokerSigma);//里面有一次验证
    printf("revoke in sRL.. \n");
    Revoker_Sigma revokerSigma;
    G1_copy(&revokerSigma.sigma0.B,&platformSigma.sigma0.B);
    BIG_copy(revokerSigma.sigma0.c,platformSigma.sigma0.c);
    BIG_copy(revokerSigma.sigma0.sf,platformSigma.sigma0.sf);
    G1_copy(&revokerSigma.sigma0.T,&platformSigma.sigma0.T);
    BIG_copy(revokerSigma.sigma0.sx,platformSigma.sigma0.sx);
    BIG_copy(revokerSigma.sigma0.sa,platformSigma.sigma0.sa);
    BIG_copy(revokerSigma.sigma0.sb,platformSigma.sigma0.sb);
    G1_copy(&revokerSigma.sigma0.K,&platformSigma.sigma0.K);
    revokerSigma.sigmai.cnt = platformSigma.sigmai.cnt;
    revokerSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*platformSigma.sigmai.cnt);
    for(int i=0;i<platformSigma.sigmai.cnt;i++){
        G1_copy(&revokerSigma.sigmai.sigmai[i].B,&platformSigma.sigmai.sigmai[i].B);
        G1_copy(&revokerSigma.sigmai.sigmai[i].K,&platformSigma.sigmai.sigmai[i].K);
        BIG_copy(revokerSigma.sigmai.sigmai[i].c,platformSigma.sigmai.sigmai[i].c);
        BIG_copy(revokerSigma.sigmai.sigmai[i].sf,platformSigma.sigmai.sigmai[i].sf);
    }
    revokerRevokeSRL(&gpk,pRL,sRL,m,&revokerSigma);


// 再次签名
    // cout << "Test Sign.." << endl;
    // char tm[] = "Test message to be signed";
    // Platform_Sigma *platformSigmaTest = new Platform_Sigma();
    // platformSigmaTest->sigma0 = new Platform_Sigma0();
    // platformSigmaTest->sigmai = new Platform_Sigmai();
    // platformSigmaTest->sigmai->cnt = sRL->cnt;
    // platformSigmaTest->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    // platformSign(gpk, tm, sRL, platformSigmaTest);

    printf("Test Sign..\n");
    char tm[] = "Test message to be signed";
    Platform_Sigma platformSigmaTest;

    platformSign(&gpk, tm, sRL, &platformSigmaTest);

    printPlatformSigma(&platformSigmaTest);

    // TODO：传输格式要注意做适配和更改
    // platform 发送 platformSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigmaTest;
    G1_copy(&verifierSigmaTest.sigma0.B,&platformSigmaTest.sigma0.B);
    BIG_copy(verifierSigmaTest.sigma0.c,platformSigmaTest.sigma0.c);
    BIG_copy(verifierSigmaTest.sigma0.sf,platformSigmaTest.sigma0.sf);
    G1_copy(&verifierSigmaTest.sigma0.T,&platformSigmaTest.sigma0.T);
    BIG_copy(verifierSigmaTest.sigma0.sx,platformSigmaTest.sigma0.sx);
    BIG_copy(verifierSigmaTest.sigma0.sa,platformSigmaTest.sigma0.sa);
    BIG_copy(verifierSigmaTest.sigma0.sb,platformSigmaTest.sigma0.sb);
    G1_copy(&verifierSigmaTest.sigma0.K,&platformSigmaTest.sigma0.K);
    verifierSigmaTest.sigmai.cnt = platformSigmaTest.sigmai.cnt;
    verifierSigmaTest.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*platformSigmaTest.sigmai.cnt);
    for(int i=0;i<platformSigmaTest.sigmai.cnt;i++){
        G1_copy(&verifierSigmaTest.sigmai.sigmai[i].B,&platformSigmaTest.sigmai.sigmai[i].B);
        G1_copy(&verifierSigmaTest.sigmai.sigmai[i].K,&platformSigmaTest.sigmai.sigmai[i].K);
        BIG_copy(verifierSigmaTest.sigmai.sigmai[i].c,platformSigmaTest.sigmai.sigmai[i].c);
        BIG_copy(verifierSigmaTest.sigmai.sigmai[i].sf,platformSigmaTest.sigmai.sigmai[i].sf);
    }

// Verify
    // cout << "Test Verify.." << endl;
    // Verifier_Sigma *verifierSigmaTest = (Verifier_Sigma*)platformSigmaTest;
    // verifierVerify(gpk, tm, pRL, verifierSigmaTest->sigmai, verifierSigmaTest->sigma0);
    printf("Verify..\n");
    verifierVerify(&gpk, tm, pRL, &verifierSigmaTest.sigmai, &verifierSigmaTest.sigma0);

}

void failTest_3(){
    // cout << "【fail-test 3】: revoke in pRL" << endl;
    printf("【fail-test 3】: revoke in pRL\n");
    // GPK *gpk = new GPK(); 
    // PPK *ppk = new PPK();

    // Public_PRL *pRL = new Public_PRL();
    // Public_SRL *sRL = new Public_SRL();


    // printf("Setup..\n");
    // issuerSetup(gpk);
    // platformPreCom();
    // verifierPreCom();
    // revokerPreCom(pRL,sRL);

    GPK gpk;
    PPK ppk;
    Public_PRL *pRL = (Public_PRL*)malloc(sizeof(Public_PRL));
    Public_SRL *sRL = (Public_SRL*)malloc(sizeof(Public_SRL));

    printf("Setup..\n");
    issuerSetup(&gpk);
    platformPreCom(&gpk);
    verifierPreCom(&gpk);
    revokerPreCom(&gpk, pRL,sRL);

    printGPK(&gpk);

    if(ECP_BLS12383_isinf(&gpk.g1))printf("g1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h1))printf("h1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h2))printf("h2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.g2))printf("g2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.w))printf("w is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.g3))printf("g3 is infinity\n");

// Join
    // cout << "Join.." << endl;
    printf("Join..\n");
    // Platform_CommC *platformCommC = new Platform_CommC();
    // Issuer_CommC *issuerCommC;

    // Issuer_CRE *issuerCre = new Issuer_CRE();
    // Platform_CRE *platformCre;

    // // platform 生成 platformCommC
    // platformJoin_1(gpk,platformCommC);
    // // platform 发送 platformCommC 给 issuer
    // // issuer 用 IssuerCommC 接收
    // issuerCommC = (Issuer_CommC*)platformCommC;

    // // issuer 生成 Issuer_CRE
    // issuerJoin_2(gpk, issuerCommC, issuerCre);
    // // issuer 发送 issuerCre 给 platform
    // // platform 用 platformCre 接收
    // platformCre = (Platform_CRE*)issuerCre;

    // // 平台生成公私钥
    // if(platformJoin_3(gpk, platformCre, ppk)) exit(0);

    Platform_CommC platformCommC;
    platformJoin_1(&gpk,&platformCommC);
    // platform 发送 platformCommC 给 issuer
    // issuer 用 IssuerCommC 接收
    Issuer_CommC issuerCommC;
    G1_copy(&issuerCommC.C,&platformCommC.C);
    BIG_copy(issuerCommC.c,platformCommC.c);
    BIG_copy(issuerCommC.sf,platformCommC.sf);
    BIG_copy(issuerCommC.sy1,platformCommC.sy1);
    printPlatformCommC(&platformCommC);

    // issuer 生成 Issuer_CRE
    Issuer_CRE issuerCre;
    issuerJoin_2(&gpk, &issuerCommC, &issuerCre);
    // issuer 发送 issuerCre 给 platform
    // platform 用 platformCre 接收
    Platform_CRE platformCre;
    // &platformCre = (Platform_CRE*)&issuerCre;
    G1_copy(&platformCre.A,&issuerCre.A);
    BIG_copy(platformCre.x,issuerCre.x);
    BIG_copy(platformCre.y2,issuerCre.y2);

    printIssuer_CRE(&issuerCre);

    // 平台生成公私钥
    if(platformJoin_3(&gpk, &platformCre, &ppk)) exit(0);
    printPPK(&ppk);
    printSK();

// revoke in pRL
    // Revoker_SK* sk_revoker = (Revoker_SK*)platformLeakSK_Test();
    // cout << "Leak the sk: " << sk_revoker << endl;
    // cout << "revoke in pRL.. " <<endl;
    // revokerRevokePRL(gpk,pRL,sk_revoker);
    SK *sk=platformLeakSK_Test();
    Revoker_SK sk_revoker;
    G1_copy(&sk_revoker.A,&sk->A);
    BIG_copy(sk_revoker.x,sk->x);
    BIG_copy(sk_revoker.y,sk->y);
    BIG_copy(sk_revoker.f,sk->f);

    printf("Leak the sk: \n");
    printSK();
    printf("revoke in pRL.. \n");
    revokerRevokePRL(&gpk,pRL,&sk_revoker);

// Sign
    // cout << "Sign.." << endl;
    // char m[] = "Test message to be signed";
    // Platform_Sigma *platformSigma = new Platform_Sigma();
    // platformSigma->sigma0 = new Platform_Sigma0();
    // platformSigma->sigmai = new Platform_Sigmai();
    // platformSigma->sigmai->cnt = sRL->cnt;
    // platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    // platformSign(gpk, m, sRL, platformSigma);

    printf("Sign..\n");
    char m[] = "Test message to be signed";
    Platform_Sigma platformSigma;

    platformSign(&gpk, m, sRL, &platformSigma);

    printPlatformSigma(&platformSigma);

    // TODO：传输格式要注意做适配和更改
    // platform 发送 platformSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigma;
    G1_copy(&verifierSigma.sigma0.B,&platformSigma.sigma0.B);
    BIG_copy(verifierSigma.sigma0.c,platformSigma.sigma0.c);
    BIG_copy(verifierSigma.sigma0.sf,platformSigma.sigma0.sf);
    G1_copy(&verifierSigma.sigma0.T,&platformSigma.sigma0.T);
    BIG_copy(verifierSigma.sigma0.sx,platformSigma.sigma0.sx);
    BIG_copy(verifierSigma.sigma0.sa,platformSigma.sigma0.sa);
    BIG_copy(verifierSigma.sigma0.sb,platformSigma.sigma0.sb);
    G1_copy(&verifierSigma.sigma0.K,&platformSigma.sigma0.K);
    verifierSigma.sigmai.cnt = platformSigma.sigmai.cnt;
    verifierSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*platformSigma.sigmai.cnt);
    for(int i=0;i<platformSigma.sigmai.cnt;i++){
        G1_copy(&verifierSigma.sigmai.sigmai[i].B,&platformSigma.sigmai.sigmai[i].B);
        G1_copy(&verifierSigma.sigmai.sigmai[i].K,&platformSigma.sigmai.sigmai[i].K);
        BIG_copy(verifierSigma.sigmai.sigmai[i].c,platformSigma.sigmai.sigmai[i].c);
        BIG_copy(verifierSigma.sigmai.sigmai[i].sf,platformSigma.sigmai.sigmai[i].sf);
    }



    


// Verify
    // cout << "Verify.." << endl;
    // Verifier_Sigma* verifierSigma = (Verifier_Sigma*)platformSigma;
    // verifierVerify(gpk, m, pRL, verifierSigma->sigmai, verifierSigma->sigma0);
    printf("Verify..\n");
    if(verifierVerify(&gpk, m, pRL, &verifierSigma.sigmai, &verifierSigma.sigma0)) exit(0);
}

int failtest_main(){
    // miracl *mip = get_mip();
    // time_t seed;

    // time(&seed);
    // irand((long)seed);


// fail_test1:改变消息内容
    failTest_1();
// fail_test2:pRL撤销后签名
    failTest_2();
// fail_test3:签名后sRL撤销，再次签名
    failTest_3();

}