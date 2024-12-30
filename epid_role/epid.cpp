#include <iostream>
#include <ctime>

#include "epid_type.h"
#include "epid_issuer.h"
#include "epid_platform.h"
#include "epid_revoker.h"
#include "epid_verifier.h"

PFC pfc(AES_SECURITY);

int main()
{
    // miracl *mip = get_mip();
    // time_t seed;

    GPK *gpk = new GPK(); 
    PPK *ppk = new PPK();

    Public_PRL *pRL = new Public_PRL();
    Public_SRL *sRL = new Public_SRL();

    // time(&seed);
    // irand((long)seed);

    printf("Setup..\n");
    issuerSetup(gpk);
    platformPreCom();
    verifierPreCom();
    revokerPreCom(pRL,sRL);

// Join
    cout << "Join.." << endl;
    Platform_CommC *platformCommC = new Platform_CommC();
    Issuer_CommC *issuerCommC;

    Issuer_CRE *issuerCre = new Issuer_CRE();
    Platform_CRE *platformCre;

    

    // platform 生成 platformCommC
    platformJoin_1(gpk,platformCommC);
    // platform 发送 platformCommC 给 issuer
    // issuer 用 IssuerCommC 接收
    issuerCommC = (Issuer_CommC*)platformCommC;

    // issuer 生成 Issuer_CRE
    issuerJoin_2(gpk, issuerCommC, issuerCre);
    // issuer 发送 issuerCre 给 platform
    // platform 用 platformCre 接收
    platformCre = (Platform_CRE*)issuerCre;

    // 平台生成公私钥
    if(platformJoin_3(gpk, platformCre, ppk)) exit(0);

// Sign
    cout << "Sign.." << endl;
    char m[] = "Test message to be signed";
    Platform_Sigma *platformSigma = new Platform_Sigma();
    platformSigma->sigma0 = new Platform_Sigma0();
    platformSigma->sigmai = new Platform_Sigmai();
    platformSigma->sigmai->cnt = sRL->cnt;
    platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    platformSign(gpk, m, sRL, platformSigma);

    // platform 发送 platformSigma 给 verifier
    // verifier 用 verifierSigma 接收，之后需要添加上m
    Verifier_Sigma *verifierSigma = (Verifier_Sigma*) platformSigma;

// Verify
    cout << "Verify.." << endl;
    if(verifierVerify(gpk, m, pRL, verifierSigma->sigmai, verifierSigma->sigma0)) exit(0);
}
