#include "epid_verifier.h"

GT vt1,vt2,vt3,vt4;
PFC *verifierPFC=&pfc;
void verifierPreCom()
{
    // verifierPFC = PFC(AES_SECURITY);

    verifierPFC->precomp_for_power(vt1);
    verifierPFC->precomp_for_power(vt2);
    verifierPFC->precomp_for_power(vt3);
    verifierPFC->precomp_for_power(vt4);
}

int verifierCheckPRL(Public_PRL *pRL, G3 *B, G3 *K){
    for(int i=0;i<pRL->cnt;i++){
        if(*K==verifierPFC->mult(*B,pRL->f[i])){
            cout << "pRL revoked! " << endl;
            return -1;
        }
    }
    return 0;
}

int verifierCheckSRL(GPK *gpk, char *m, Verifier_Sigmai *sigmai, G3 *B, G3 *K){
    for(int i=0;i<sigmai->cnt;i++){
        Verifier_BK_SPK *s = &(sigmai->sigmai[i]);
        G3 R = verifierPFC->mult(*B,s->sf)+verifierPFC->mult(*K,(-1) * s->c);
        G3 Ri = verifierPFC->mult(s->B,s->sf)+verifierPFC->mult(s->K,(-1)*s->c);
        verifierPFC->start_hash();
        verifierPFC->add_to_hash(gpk->p);
        verifierPFC->add_to_hash(gpk->g1);
        verifierPFC->add_to_hash(gpk->g2);
        verifierPFC->add_to_hash(gpk->g3);
        verifierPFC->add_to_hash(gpk->h1);
        verifierPFC->add_to_hash(gpk->h2);
        verifierPFC->add_to_hash(gpk->w);
        verifierPFC->add_to_hash(*B);
        verifierPFC->add_to_hash(*K);
        verifierPFC->add_to_hash(R);
        verifierPFC->add_to_hash(s->B);
        verifierPFC->add_to_hash(s->K);
        verifierPFC->add_to_hash(Ri);
        verifierPFC->add_to_hash(m);
        Big c = verifierPFC->finish_hash_to_group();
        if(c == s->c){
            cout << "sRL revoked! " << endl;
            return -1;
        }
    }
    return 0;
}

int verifierVerify(GPK *gpk, char *m, Public_PRL *pRL, Verifier_Sigmai *sigmai, Verifier_Sigma0 *sigma0)
{
    // 验证sigma0的知识证明
    G3 R1 = verifierPFC->mult(sigma0->B, sigma0->sf) + verifierPFC->mult(sigma0->K, (-1) * sigma0->c);
    GT R2 = verifierPFC->pairing(verifierPFC->mult(gpk->g2, (-1) * sigma0->sx) + verifierPFC->mult(gpk->w, (-1) * sigma0->c), sigma0->T) * verifierPFC->power(vt2, sigma0->sf) * verifierPFC->power(vt3, sigma0->sb) * verifierPFC->power(vt4, sigma0->sa) * verifierPFC->power(vt1, sigma0->c);
    verifierPFC->start_hash();
    verifierPFC->add_to_hash(gpk->p);
    verifierPFC->add_to_hash(gpk->g1);
    verifierPFC->add_to_hash(gpk->g2);
    verifierPFC->add_to_hash(gpk->g3);
    verifierPFC->add_to_hash(gpk->h1);
    verifierPFC->add_to_hash(gpk->h2);
    verifierPFC->add_to_hash(gpk->w);
    verifierPFC->add_to_hash(sigma0->B);
    verifierPFC->add_to_hash(sigma0->K);
    verifierPFC->add_to_hash(sigma0->T);
    verifierPFC->add_to_hash(R1);
    verifierPFC->add_to_hash(R2);
    verifierPFC->add_to_hash(m);
    Big c = verifierPFC->finish_hash_to_group();

    if (c != sigma0->c)
    {
        cout << "Verification failed, aborting.. " << endl;
        return -1;
    }
//检查pRL和sRL
    if(verifierCheckPRL(pRL, &sigma0->B, &sigma0->K))return -1;
    if(verifierCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K))return -1;

    cout << "Verification succeeds! " << endl;

    return 0;
}