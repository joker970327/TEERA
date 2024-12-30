#include <iostream>
#include <ctime>

#include "epid_type.h"
#include "epid_issuer.h"
#include "epid_platform.h"
#include "epid_revoker.h"
#include "epid_verifier.h"

PFC pfc(AES_SECURITY);

void failTest_1(){
    cout << "【fail-test 1】: change message" << endl;
    GPK *gpk = new GPK(); 
    PPK *ppk = new PPK();

    Public_PRL *pRL = new Public_PRL();
    Public_SRL *sRL = new Public_SRL();


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
// change message.. 
// Sign
    cout << "Sign.." << endl;
    char m[] = "Test message to be signed";

    Platform_Sigma *platformSigma = new Platform_Sigma();
    platformSigma->sigma0 = new Platform_Sigma0();
    platformSigma->sigmai = new Platform_Sigmai();
    platformSigma->sigmai->cnt = sRL->cnt;
    platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    platformSign(gpk, m, sRL, platformSigma);
    cout << "m: \"" << m <<"\"";
    m[0] = 't';
    cout<<" is changed into: \""<<m<<"\""<<endl;

// Verify
    cout << "Verify.." << endl;
    Verifier_Sigma *verifierSigma = (Verifier_Sigma*)platformSigma;
    verifierVerify(gpk, m, pRL, verifierSigma->sigmai, verifierSigma->sigma0);
}

void failTest_2(){
    cout << "【fail-test 2】: revoke in sRL" << endl;
    GPK *gpk = new GPK(); 
    PPK *ppk = new PPK();

    Public_PRL *pRL = new Public_PRL();
    Public_SRL *sRL = new Public_SRL();


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
// revoke in sRL
// Sign
    cout << "Original Sign.." << endl;
    char m[] = "Test message to be signed";

    Platform_Sigma *platformSigma = new Platform_Sigma();
    platformSigma->sigma0 = new Platform_Sigma0();
    platformSigma->sigmai = new Platform_Sigmai();
    platformSigma->sigmai->cnt = sRL->cnt;
    platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    platformSign(gpk, m, sRL, platformSigma);

// Verify
    cout << "Original Verify.." << endl;
    Verifier_Sigma *verifierSigma = (Verifier_Sigma*)platformSigma;
    verifierVerify(gpk, m, pRL, verifierSigma->sigmai, verifierSigma->sigma0);

// sRL 撤销
    cout << "revoke in sRL.. "<<endl;
    Revoker_Sigma *revokerSigma = (Revoker_Sigma*)platformSigma;
    revokerRevokeSRL(gpk,pRL,sRL,m,revokerSigma);//里面有一次验证

// 再次签名
    cout << "Test Sign.." << endl;
    char tm[] = "Test message to be signed";
    Platform_Sigma *platformSigmaTest = new Platform_Sigma();
    platformSigmaTest->sigma0 = new Platform_Sigma0();
    platformSigmaTest->sigmai = new Platform_Sigmai();
    platformSigmaTest->sigmai->cnt = sRL->cnt;
    platformSigmaTest->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    platformSign(gpk, tm, sRL, platformSigmaTest);

// Verify
    cout << "Test Verify.." << endl;
    Verifier_Sigma *verifierSigmaTest = (Verifier_Sigma*)platformSigmaTest;
    verifierVerify(gpk, tm, pRL, verifierSigmaTest->sigmai, verifierSigmaTest->sigma0);

}

void failTest_3(){
    cout << "【fail-test 3】: revoke in pRL" << endl;
    GPK *gpk = new GPK(); 
    PPK *ppk = new PPK();

    Public_PRL *pRL = new Public_PRL();
    Public_SRL *sRL = new Public_SRL();


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

// revoke in pRL
    Revoker_SK* sk_revoker = (Revoker_SK*)platformLeakSK_Test();
    cout << "Leak the sk: " << sk_revoker << endl;
    cout << "revoke in pRL.. " <<endl;
    revokerRevokePRL(gpk,pRL,sk_revoker);

// Sign
    cout << "Sign.." << endl;
    char m[] = "Test message to be signed";
    Platform_Sigma *platformSigma = new Platform_Sigma();
    platformSigma->sigma0 = new Platform_Sigma0();
    platformSigma->sigmai = new Platform_Sigmai();
    platformSigma->sigmai->cnt = sRL->cnt;
    platformSigma->sigmai->sigmai = new Platform_BK_SPK[sRL->cnt];

    platformSign(gpk, m, sRL, platformSigma);


// Verify
    cout << "Verify.." << endl;
    Verifier_Sigma* verifierSigma = (Verifier_Sigma*)platformSigma;
    verifierVerify(gpk, m, pRL, verifierSigma->sigmai, verifierSigma->sigma0);
}

int main(){
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