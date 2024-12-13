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
    miracl *mip = get_mip();
    time_t seed;

    //GPK *gpk = (GPK *)malloc(sizeof(GPK));   
    GPK *gpk = new GPK(); 
    PRL *pRL = new PRL();
    SRL *sRL = new SRL();

    time(&seed);
    irand((long)seed);

    printf("Setup..\n");
    issuerSetup(gpk);
    platformPreCom();
    verifierPreCom();
    revokerPreCom();

    // Join
    cout << "Join" << endl;
    CommC *commC = platformJoin_1(gpk);
    CRE *cre = issuerJoin_2(gpk, commC);
    PPK *ppk = platformJoin_3(gpk, cre);

    // Sign
    cout << "Sign" << endl;
    char m[] = "Test message to be signed";
    Sigma *sigma = platformSign(gpk, m, sRL);

    // Verify
    cout << "Verify" << endl;
    verifierVerify(gpk, m, pRL, sigma->sigmai, sigma->sigma0);
}