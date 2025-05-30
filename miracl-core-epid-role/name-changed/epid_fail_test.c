// #include <iostream>
// #include <ctime>

#include "epid_type.h"
#include "epid_issuer.h"
#include "epid_signer.h"
#include "epid_revokeManager.h"
#include "epid_verifier.h"

// PFC pfc(AES_SECURITY);

void failTest_1(){
    printf("【fail-test 1】: change message\n");

// Setup
    GPK gpk;
    PPK ppk;
    Public_PRL *pRL = (Public_PRL*)malloc(sizeof(Public_PRL));
    Public_SRL *sRL = (Public_SRL*)malloc(sizeof(Public_SRL));

    printf("Setup..\n");
    issuerSetup(&gpk);
    signerPreCom(&gpk);
    verifierPreCom(&gpk);
    revokeManagerPreCom(&gpk, pRL,sRL);

    printGPK(&gpk);

    if(ECP_BLS12383_isinf(&gpk.g1))printf("g1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h1))printf("h1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h2))printf("h2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.g2))printf("g2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.w))printf("w is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.g3))printf("g3 is infinity\n");

// Join
    printf("Join..\n");

    // 平台生成公私钥
    Platform_CommC signerCommC;
    signerJoin_1(&gpk,&signerCommC);
    // signer 发送 signerCommC 给 issuer
    // issuer 用 IssuerCommC 接收
    Issuer_CommC issuerCommC;
    G1_copy(&issuerCommC.C,&signerCommC.C);
    BIG_copy(issuerCommC.c,signerCommC.c);
    BIG_copy(issuerCommC.sf,signerCommC.sf);
    BIG_copy(issuerCommC.sy1,signerCommC.sy1);
    printPlatformCommC(&signerCommC);

    // issuer 生成 Issuer_CRE
    Issuer_CRE issuerCre;
    issuerJoin_2(&gpk, &issuerCommC, &issuerCre);
    // issuer 发送 issuerCre 给 signer
    // signer 用 signerCre 接收
    Platform_CRE signerCre;
    G1_copy(&signerCre.A,&issuerCre.A);
    BIG_copy(signerCre.x,issuerCre.x);
    BIG_copy(signerCre.y2,issuerCre.y2);

    printIssuer_CRE(&issuerCre);

    // 平台生成公私钥
    if(signerJoin_3(&gpk, &signerCre, &ppk)) exit(0);
    printPPK(&ppk);
    printSK();
// change message.. 
// Sign

    printf("Sign..\n");
    char m[] = "Test message to be signed";
    Platform_Sigma signerSigma;

    signerSign(&gpk, m, sRL, &signerSigma);

    printPlatformSigma(&signerSigma);

    // signer 发送 signerSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigma;
    G1_copy(&verifierSigma.sigma0.B,&signerSigma.sigma0.B);
    BIG_copy(verifierSigma.sigma0.c,signerSigma.sigma0.c);
    BIG_copy(verifierSigma.sigma0.sf,signerSigma.sigma0.sf);
    G1_copy(&verifierSigma.sigma0.T,&signerSigma.sigma0.T);
    BIG_copy(verifierSigma.sigma0.sx,signerSigma.sigma0.sx);
    BIG_copy(verifierSigma.sigma0.sa,signerSigma.sigma0.sa);
    BIG_copy(verifierSigma.sigma0.sb,signerSigma.sigma0.sb);
    G1_copy(&verifierSigma.sigma0.K,&signerSigma.sigma0.K);
    verifierSigma.sigmai.cnt = signerSigma.sigmai.cnt;
    verifierSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*signerSigma.sigmai.cnt);
    for(int i=0;i<signerSigma.sigmai.cnt;i++){
        G1_copy(&verifierSigma.sigmai.sigmai[i].B,&signerSigma.sigmai.sigmai[i].B);
        G1_copy(&verifierSigma.sigmai.sigmai[i].K,&signerSigma.sigmai.sigmai[i].K);
        BIG_copy(verifierSigma.sigmai.sigmai[i].c,signerSigma.sigmai.sigmai[i].c);
        BIG_copy(verifierSigma.sigmai.sigmai[i].sf,signerSigma.sigmai.sigmai[i].sf);
    }

    printf("m: \"%s\"",m);
    m[0] = 't';
    printf(" is changed into: \"%s\"\n",m);

// Verify
    printf("Verify..\n");
    verifierVerify(&gpk, m, pRL, &verifierSigma.sigmai, &verifierSigma.sigma0);
}

void failTest_2(){
    printf("【fail-test 2】: revoke in sRL\n");

    GPK gpk;
    PPK ppk;
    Public_PRL *pRL = (Public_PRL*)malloc(sizeof(Public_PRL));
    Public_SRL *sRL = (Public_SRL*)malloc(sizeof(Public_SRL));

    printf("Setup..\n");
    issuerSetup(&gpk);
    signerPreCom(&gpk);
    verifierPreCom(&gpk);
    revokeManagerPreCom(&gpk, pRL,sRL);

    printGPK(&gpk);

    if(ECP_BLS12383_isinf(&gpk.g1))printf("g1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h1))printf("h1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h2))printf("h2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.g2))printf("g2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.w))printf("w is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.g3))printf("g3 is infinity\n");

// Join
    printf("Join..\n");

    // signer 生成 signerCommC
    // signer 发送 signerCommC 给 issuer
    // issuer 用 IssuerCommC 接收

    // issuer 生成 Issuer_CRE
    // issuer 发送 issuerCre 给 signer
    // signer 用 signerCre 接收

    // 平台生成公私钥

    Platform_CommC signerCommC;
    signerJoin_1(&gpk,&signerCommC);
    // signer 发送 signerCommC 给 issuer
    // issuer 用 IssuerCommC 接收
    Issuer_CommC issuerCommC;
    G1_copy(&issuerCommC.C,&signerCommC.C);
    BIG_copy(issuerCommC.c,signerCommC.c);
    BIG_copy(issuerCommC.sf,signerCommC.sf);
    BIG_copy(issuerCommC.sy1,signerCommC.sy1);
    printPlatformCommC(&signerCommC);

    // issuer 生成 Issuer_CRE
    Issuer_CRE issuerCre;
    issuerJoin_2(&gpk, &issuerCommC, &issuerCre);
    // issuer 发送 issuerCre 给 signer
    // signer 用 signerCre 接收
    Platform_CRE signerCre;
    G1_copy(&signerCre.A,&issuerCre.A);
    BIG_copy(signerCre.x,issuerCre.x);
    BIG_copy(signerCre.y2,issuerCre.y2);

    printIssuer_CRE(&issuerCre);

    // 平台生成公私钥
    if(signerJoin_3(&gpk, &signerCre, &ppk)) exit(0);
    printPPK(&ppk);
    printSK();
// revoke in sRL
// Sign

    printf("Original Sign..\n");
    char m[] = "Test message to be signed";
    Platform_Sigma signerSigma;

    signerSign(&gpk, m, sRL, &signerSigma);

    printPlatformSigma(&signerSigma);

    // signer 发送 signerSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigma;
    G1_copy(&verifierSigma.sigma0.B,&signerSigma.sigma0.B);
    BIG_copy(verifierSigma.sigma0.c,signerSigma.sigma0.c);
    BIG_copy(verifierSigma.sigma0.sf,signerSigma.sigma0.sf);
    G1_copy(&verifierSigma.sigma0.T,&signerSigma.sigma0.T);
    BIG_copy(verifierSigma.sigma0.sx,signerSigma.sigma0.sx);
    BIG_copy(verifierSigma.sigma0.sa,signerSigma.sigma0.sa);
    BIG_copy(verifierSigma.sigma0.sb,signerSigma.sigma0.sb);
    G1_copy(&verifierSigma.sigma0.K,&signerSigma.sigma0.K);
    verifierSigma.sigmai.cnt = signerSigma.sigmai.cnt;
    verifierSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*signerSigma.sigmai.cnt);
    for(int i=0;i<signerSigma.sigmai.cnt;i++){
        G1_copy(&verifierSigma.sigmai.sigmai[i].B,&signerSigma.sigmai.sigmai[i].B);
        G1_copy(&verifierSigma.sigmai.sigmai[i].K,&signerSigma.sigmai.sigmai[i].K);
        BIG_copy(verifierSigma.sigmai.sigmai[i].c,signerSigma.sigmai.sigmai[i].c);
        BIG_copy(verifierSigma.sigmai.sigmai[i].sf,signerSigma.sigmai.sigmai[i].sf);
    }

// Verify

// sRL 撤销
    printf("revoke in sRL.. \n");
    Revoker_Sigma revokeManagerSigma;
    G1_copy(&revokeManagerSigma.sigma0.B,&signerSigma.sigma0.B);
    BIG_copy(revokeManagerSigma.sigma0.c,signerSigma.sigma0.c);
    BIG_copy(revokeManagerSigma.sigma0.sf,signerSigma.sigma0.sf);
    G1_copy(&revokeManagerSigma.sigma0.T,&signerSigma.sigma0.T);
    BIG_copy(revokeManagerSigma.sigma0.sx,signerSigma.sigma0.sx);
    BIG_copy(revokeManagerSigma.sigma0.sa,signerSigma.sigma0.sa);
    BIG_copy(revokeManagerSigma.sigma0.sb,signerSigma.sigma0.sb);
    G1_copy(&revokeManagerSigma.sigma0.K,&signerSigma.sigma0.K);
    revokeManagerSigma.sigmai.cnt = signerSigma.sigmai.cnt;
    revokeManagerSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*signerSigma.sigmai.cnt);
    for(int i=0;i<signerSigma.sigmai.cnt;i++){
        G1_copy(&revokeManagerSigma.sigmai.sigmai[i].B,&signerSigma.sigmai.sigmai[i].B);
        G1_copy(&revokeManagerSigma.sigmai.sigmai[i].K,&signerSigma.sigmai.sigmai[i].K);
        BIG_copy(revokeManagerSigma.sigmai.sigmai[i].c,signerSigma.sigmai.sigmai[i].c);
        BIG_copy(revokeManagerSigma.sigmai.sigmai[i].sf,signerSigma.sigmai.sigmai[i].sf);
    }
    revokeManagerRevokeSRL(&gpk,pRL,sRL,m,&revokeManagerSigma);


// 再次签名

    printf("Test Sign..\n");
    char tm[] = "Test message to be signed";
    Platform_Sigma signerSigmaTest;

    signerSign(&gpk, tm, sRL, &signerSigmaTest);

    printPlatformSigma(&signerSigmaTest);

    // signer 发送 signerSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigmaTest;
    G1_copy(&verifierSigmaTest.sigma0.B,&signerSigmaTest.sigma0.B);
    BIG_copy(verifierSigmaTest.sigma0.c,signerSigmaTest.sigma0.c);
    BIG_copy(verifierSigmaTest.sigma0.sf,signerSigmaTest.sigma0.sf);
    G1_copy(&verifierSigmaTest.sigma0.T,&signerSigmaTest.sigma0.T);
    BIG_copy(verifierSigmaTest.sigma0.sx,signerSigmaTest.sigma0.sx);
    BIG_copy(verifierSigmaTest.sigma0.sa,signerSigmaTest.sigma0.sa);
    BIG_copy(verifierSigmaTest.sigma0.sb,signerSigmaTest.sigma0.sb);
    G1_copy(&verifierSigmaTest.sigma0.K,&signerSigmaTest.sigma0.K);
    verifierSigmaTest.sigmai.cnt = signerSigmaTest.sigmai.cnt;
    verifierSigmaTest.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*signerSigmaTest.sigmai.cnt);
    for(int i=0;i<signerSigmaTest.sigmai.cnt;i++){
        G1_copy(&verifierSigmaTest.sigmai.sigmai[i].B,&signerSigmaTest.sigmai.sigmai[i].B);
        G1_copy(&verifierSigmaTest.sigmai.sigmai[i].K,&signerSigmaTest.sigmai.sigmai[i].K);
        BIG_copy(verifierSigmaTest.sigmai.sigmai[i].c,signerSigmaTest.sigmai.sigmai[i].c);
        BIG_copy(verifierSigmaTest.sigmai.sigmai[i].sf,signerSigmaTest.sigmai.sigmai[i].sf);
    }

// Verify
    printf("Verify..\n");
    verifierVerify(&gpk, tm, pRL, &verifierSigmaTest.sigmai, &verifierSigmaTest.sigma0);

}

void failTest_3(){
    printf("【fail-test 3】: revoke in pRL\n");

    GPK gpk;
    PPK ppk;
    Public_PRL *pRL = (Public_PRL*)malloc(sizeof(Public_PRL));
    Public_SRL *sRL = (Public_SRL*)malloc(sizeof(Public_SRL));

    printf("Setup..\n");
    issuerSetup(&gpk);
    signerPreCom(&gpk);
    verifierPreCom(&gpk);
    revokeManagerPreCom(&gpk, pRL,sRL);

    printGPK(&gpk);

    if(ECP_BLS12383_isinf(&gpk.g1))printf("g1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h1))printf("h1 is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.h2))printf("h2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.g2))printf("g2 is infinity\n");
    if(ECP2_BLS12383_isinf(&gpk.w))printf("w is infinity\n");
    if(ECP_BLS12383_isinf(&gpk.g3))printf("g3 is infinity\n");

// Join
    printf("Join..\n");

    // signer 生成 signerCommC
    // signer 发送 signerCommC 给 issuer
    // issuer 用 IssuerCommC 接收

    // issuer 生成 Issuer_CRE
    // issuer 发送 issuerCre 给 signer
    // signer 用 signerCre 接收

    // 平台生成公私钥

    Platform_CommC signerCommC;
    signerJoin_1(&gpk,&signerCommC);
    // signer 发送 signerCommC 给 issuer
    // issuer 用 IssuerCommC 接收
    Issuer_CommC issuerCommC;
    G1_copy(&issuerCommC.C,&signerCommC.C);
    BIG_copy(issuerCommC.c,signerCommC.c);
    BIG_copy(issuerCommC.sf,signerCommC.sf);
    BIG_copy(issuerCommC.sy1,signerCommC.sy1);
    printPlatformCommC(&signerCommC);

    // issuer 生成 Issuer_CRE
    Issuer_CRE issuerCre;
    issuerJoin_2(&gpk, &issuerCommC, &issuerCre);
    // issuer 发送 issuerCre 给 signer
    // signer 用 signerCre 接收
    Platform_CRE signerCre;
    G1_copy(&signerCre.A,&issuerCre.A);
    BIG_copy(signerCre.x,issuerCre.x);
    BIG_copy(signerCre.y2,issuerCre.y2);

    printIssuer_CRE(&issuerCre);

    // 平台生成公私钥
    if(signerJoin_3(&gpk, &signerCre, &ppk)) exit(0);
    printPPK(&ppk);
    printSK();

// revoke in pRL

    SK *sk=signerLeakSK_Test();
    Revoker_SK sk_revokeManager;
    G1_copy(&sk_revokeManager.A,&sk->A);
    BIG_copy(sk_revokeManager.x,sk->x);
    BIG_copy(sk_revokeManager.y,sk->y);
    BIG_copy(sk_revokeManager.f,sk->f);

    printf("Leak the sk: \n");
    printSK();
    printf("revoke in pRL.. \n");
    revokeManagerRevokePRL(&gpk,pRL,&sk_revokeManager);

// Sign

    printf("Sign..\n");
    char m[] = "Test message to be signed";
    Platform_Sigma signerSigma;

    signerSign(&gpk, m, sRL, &signerSigma);

    printPlatformSigma(&signerSigma);

    // signer 发送 signerSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma verifierSigma;
    G1_copy(&verifierSigma.sigma0.B,&signerSigma.sigma0.B);
    BIG_copy(verifierSigma.sigma0.c,signerSigma.sigma0.c);
    BIG_copy(verifierSigma.sigma0.sf,signerSigma.sigma0.sf);
    G1_copy(&verifierSigma.sigma0.T,&signerSigma.sigma0.T);
    BIG_copy(verifierSigma.sigma0.sx,signerSigma.sigma0.sx);
    BIG_copy(verifierSigma.sigma0.sa,signerSigma.sigma0.sa);
    BIG_copy(verifierSigma.sigma0.sb,signerSigma.sigma0.sb);
    G1_copy(&verifierSigma.sigma0.K,&signerSigma.sigma0.K);
    verifierSigma.sigmai.cnt = signerSigma.sigmai.cnt;
    verifierSigma.sigmai.sigmai = (Verifier_BK_SPK*)malloc(sizeof(Verifier_BK_SPK)*signerSigma.sigmai.cnt);
    for(int i=0;i<signerSigma.sigmai.cnt;i++){
        G1_copy(&verifierSigma.sigmai.sigmai[i].B,&signerSigma.sigmai.sigmai[i].B);
        G1_copy(&verifierSigma.sigmai.sigmai[i].K,&signerSigma.sigmai.sigmai[i].K);
        BIG_copy(verifierSigma.sigmai.sigmai[i].c,signerSigma.sigmai.sigmai[i].c);
        BIG_copy(verifierSigma.sigmai.sigmai[i].sf,signerSigma.sigmai.sigmai[i].sf);
    }



    


// Verify
    printf("Verify..\n");
    if(verifierVerify(&gpk, m, pRL, &verifierSigma.sigmai, &verifierSigma.sigma0)) exit(0);
}

int main(){

// fail_test1:改变消息内容
    failTest_1();
// fail_test2:pRL撤销后签名
    failTest_2();
// fail_test3:签名后sRL撤销，再次签名
    failTest_3();

}