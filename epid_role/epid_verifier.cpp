#include "epid_verifier.h"

GT vt1,vt2,vt3,vt4;

void verifierPreCom()
{
    pfc.precomp_for_power(vt1);
    pfc.precomp_for_power(vt2);
    pfc.precomp_for_power(vt3);
    pfc.precomp_for_power(vt4);
}

void verifierVerify(GPK *gpk, char *m, PRL *pRL, Sigmai *sigmai, Sigma0 *sigma0)
{
    // 验证sigma0的知识证明
    G3 R1 = pfc.mult(sigma0->B, sigma0->sf) + pfc.mult(sigma0->K, (-1) * sigma0->c);
    GT R2 = pfc.pairing(pfc.mult(gpk->g2, (-1) * sigma0->sx) + pfc.mult(gpk->w, (-1) * sigma0->c), sigma0->T) * pfc.power(vt2, sigma0->sf) * pfc.power(vt3, sigma0->sb) * pfc.power(vt4, sigma0->sa) * pfc.power(vt1, sigma0->c);
    pfc.start_hash();
    pfc.add_to_hash(gpk->p);
    pfc.add_to_hash(gpk->g1);
    pfc.add_to_hash(gpk->g2);
    pfc.add_to_hash(gpk->g3);
    pfc.add_to_hash(gpk->h1);
    pfc.add_to_hash(gpk->h2);
    pfc.add_to_hash(gpk->w);
    pfc.add_to_hash(sigma0->B);
    pfc.add_to_hash(sigma0->K);
    pfc.add_to_hash(sigma0->T);
    pfc.add_to_hash(R1);
    pfc.add_to_hash(R2);
    pfc.add_to_hash(m);
    Big c = pfc.finish_hash_to_group();

    if (c != sigma0->c)
    {
        cout << "Verification failed, aborting.. " << endl;
        exit(0);
    }
//检查pRL和sRL
    verifierCheckPRL(pRL, &sigma0->B, &sigma0->K);
    verifierCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K);

    cout << "Verification succeeds! " << endl;
}

void verifierCheckPRL(PRL *pRL, G3 *B, G3 *K){
    PRLNode *p = pRL->head;
    while(p!=NULL){
        if(*K==pfc.mult(*B,p->f)){
            cout << "pRL revoked! " << endl;
            exit(0);
        }
        p = p->next;
    }
}

void verifierCheckSRL(GPK *gpk, char *m, Sigmai *sigmai, G3 *B, G3 *K){
    BK_SPK *s=sigmai->head;
    while(s!=NULL){
        G3 R = pfc.mult(*B,s->sf)+pfc.mult(*K,(-1) * s->c);
        G3 Ri = pfc.mult(s->B,s->sf)+pfc.mult(s->K,(-1)*s->c);
        pfc.start_hash();
        pfc.add_to_hash(gpk->p);
        pfc.add_to_hash(gpk->g1);
        pfc.add_to_hash(gpk->g2);
        pfc.add_to_hash(gpk->g3);
        pfc.add_to_hash(gpk->h1);
        pfc.add_to_hash(gpk->h2);
        pfc.add_to_hash(gpk->w);
        pfc.add_to_hash(*B);
        pfc.add_to_hash(*K);
        pfc.add_to_hash(R);
        pfc.add_to_hash(s->B);
        pfc.add_to_hash(s->K);
        pfc.add_to_hash(Ri);
        pfc.add_to_hash(m);
        Big c = pfc.finish_hash_to_group();
        if(c == s->c){
            cout << "sRL revoked! " << endl;
            exit(0);
        }
        s = s->next;
    }
}