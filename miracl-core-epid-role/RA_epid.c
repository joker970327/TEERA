// #include <iostream>
// #include <ctime>

#include "RA_epid_type.h"
#include "RA_epid_issuer.h"
#include "RA_epid_platform.h"
#include "RA_epid_revoker.h"
#include "RA_epid_verifier.h"

int main()
{
    // GPK *gpk = (GPK*)malloc(sizeof(GPK));
    // PPK *ppk = (PPK*)malloc(sizeof(PPK));
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
    printf("Join..\n");
    // Platform_CommC *platformCommC = new Platform_CommC();
    // Issuer_CommC *issuerCommC;

    // Issuer_CRE *issuerCre = new Issuer_CRE();
    // Platform_CRE *platformCre;

    Platform_CommC platformCommC;
    // platform 生成 platformCommC
    platformJoin_1(&gpk,&platformCommC);
    // platform 发送 platformCommC 给 issuer
    // printPlatformCommC(platformCommC);
    // issuer 用 IssuerCommC 接收
    Issuer_CommC issuerCommC;
    // issuerCommC = (Issuer_CommC*)&platformCommC;
    G1_copy(&issuerCommC.C,&platformCommC.C);
    BIG_copy(issuerCommC.c,platformCommC.c);
    BIG_copy(issuerCommC.sf,platformCommC.sf);
    BIG_copy(issuerCommC.sy1,platformCommC.sy1);
    printPlatformCommC(&platformCommC);

    // issuer 生成 Issuer_CRE
    Issuer_CRE issuerCre;
    issuerJoin_2(&gpk, &issuerCommC, &issuerCre);
    // issuer 发送 issuerCre 给 platform
    // printIssuer_CRE(issuerCre);
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

// Sign
    // cout << "Sign.." << endl;
    printf("Sign..\n");
    char m[] = "Test message to be signed";
    // Platform_Sigma *platformSigma = new Platform_Sigma();
    Platform_Sigma platformSigma;
    // platformSigma->sigma0 = new Platform_Sigma0();
    // platformSigma->sigmai = new Platform_Sigmai();
    // platformSigma.sigmai->cnt = sRL->cnt;
    // platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    platformSign(&gpk, m, sRL, &platformSigma);

    printPlatformSigma(&platformSigma);

    // TODO：传输格式要注意做适配和更改
    // platform 发送 platformSigma 给 verifier
    // printPlatformSigma(platformSigma);
    // verifier 用 verifierSigma 接收，之后需要添加上m
    // Verifier_Sigma *verifierSigma = (Verifier_Sigma*) platformSigma;
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
    printf("Verify..\n");
    if(verifierVerify(&gpk, m, pRL, &verifierSigma.sigmai, &verifierSigma.sigma0)) exit(0);
}

void printCurve(G1* g1){
    
}

void printPublic_SRLNode(Public_SRLNode *sRLNode){
    // cout<<"type: Public_SRLNode"<<endl;
    // cout<<"    B.g: "<<sRLNode->B.g<<endl;
    // cout<<"        B size: "<<sizeof(sRLNode->B)<<endl;
    // cout<<"    K.g: "<<sRLNode->K.g<<endl;
    // cout<<"        K size: "<<sizeof(sRLNode->K)<<endl;
    // cout<<"Public_SRLNode size: "<<sizeof(*sRLNode)<<endl;
    printf("    B--\n    ");
    display_G1(&sRLNode->B);
    printf("    K--\n    ");
    display_G1(&sRLNode->K);
}

void printPublic_SRL(Public_SRL *sRL){
    // cout<<"type: Public_SRL"<<endl;
    // cout<<"    cnt: "<<sRL->cnt<<endl;
    // cout<<"    sRLNode: "<<endl;
    printf("[sRL]Public\n");
    for(int i=0;i<sRL->cnt;i++){
        printPublic_SRLNode(sRL->sRLNode+i);
    }
    // cout<<"Public_SRL size: "<<sizeof(*sRL)<<endl;
}

void printPublic_PRL(Public_PRL *pRL){
    // cout<<"type: Public_PRL"<<endl;
    // cout<<"    cnt: "<<pRL->cnt<<endl;
    printf("[pRL]Public\n");
    for(int i=0;i<pRL->cnt;i++){
        // cout<<"    f["<<i<<"]: "<<pRL->f[i]<<endl;
        printf("    f[%d]--\n    ",i);
        display_Big(pRL->f[i]);
    }
    // cout<<"Public_PRL size: "<<sizeof(*pRL)<<endl;
}
