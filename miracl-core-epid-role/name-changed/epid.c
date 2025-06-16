// #include <iostream>
// #include <ctime>

#include "epid_type.h"
#include "epid_issuer.h"
#include "epid_signer.h"
#include "epid_revokeManager.h"
#include "epid_verifier.h"

int main()
{
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

    Platform_CommC signerCommC;
    // signer 生成 signerCommC
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

    // 2.Join -- 4) 
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

// Sign
    // cout << "Sign.." << endl;
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
    // cout << "Verify.." << endl;
    printf("Verify..\n");
    if(verifierVerify(&gpk, m, pRL, &verifierSigma.sigmai, &verifierSigma.sigma0)) exit(0);
}

void printCurve(G1* g1){
    
}

void printPublic_SRLNode(Public_SRLNode *sRLNode){
    printf("    B--\n    ");
    display_G1(&sRLNode->B);
    printf("    K--\n    ");
    display_G1(&sRLNode->K);
}

void printPublic_SRL(Public_SRL *sRL){
    printf("[sRL]Public\n");
    for(int i=0;i<sRL->cnt;i++){
        printPublic_SRLNode(sRL->sRLNode+i);
    }
}

void printPublic_PRL(Public_PRL *pRL){
    printf("[pRL]Public\n");
    for(int i=0;i<pRL->cnt;i++){
        printf("    f[%d]--\n    ",i);
        display_Big(pRL->f[i]);
    }
}
