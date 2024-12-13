#include "epid_revoker.h"

GT rt1,rt2,rt3,rt4;

void revokerPreCom()
{
    pfc.precomp_for_power(rt1);
    pfc.precomp_for_power(rt2);
    pfc.precomp_for_power(rt3);
    pfc.precomp_for_power(rt4);
}
void revokerCheckPRL(PRL *pRL, G3 *B, G3 *K){
    PRLNode *p = pRL->head;
    while(p!=NULL){
        if(*K==pfc.mult(*B,p->f)){
            cout << "pRL revoked! " << endl;
            exit(0);
        }
        p = p->next;
    }
}

void revokerCheckSRL(GPK *gpk, char *m, Sigmai *sigmai, G3 *B, G3 *K){
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

void revokerRevokePRL(GPK *gpk, PRL *pRL, SK *sk){
    G2 wxg2 = gpk->w + pfc.mult(gpk->g2, sk->x);
    G1 g1h1fh2y = -(pfc.mult(gpk->h1, sk->f) + pfc.mult(gpk->h2, sk->y) + gpk->g1);
    G1 *e1[2];
    G2 *e2[2];
    e1[0] = &sk->A;
    e1[1] = &g1h1fh2y;
    e2[0] = &wxg2;
    e2[1] = &gpk->g2;
    if (pfc.multi_pairing(2, e2, e1) != 1)
    {
        cout << "Pairing verification failed, aborting.. " << endl;
        exit(0);
    }

    // PRLNode *tmp = (PRLNode*)malloc(sizeof(PRLNode));
    PRLNode *tmp = new PRLNode();
    tmp->f = sk->f;
    pRL->tail->next = tmp;
    pRL->tail = tmp;
}
void revokerRevokeSRL(GPK *gpk, PRL *pRL, SRL *sRL, char *m, Sigma *sigma){
    revokerVerify(gpk,m,pRL,sigma->sigmai,sigma->sigma0);
    // BK *tmp = (BK*)malloc(sizeof(BK));
    BK *tmp = new BK();
    tmp->B = sigma->sigma0->B;
    tmp->K = sigma->sigma0->K;
    sRL->tail->next = tmp;
    sRL->tail = tmp;
}

void revokerVerify(GPK *gpk, char *m, PRL *pRL, Sigmai *sigmai, Sigma0 *sigma0)
{
    // 验证sigma0的知识证明
    G3 R1 = pfc.mult(sigma0->B, sigma0->sf) + pfc.mult(sigma0->K, (-1) * sigma0->c);
    GT R2 = pfc.pairing(pfc.mult(gpk->g2, (-1) * sigma0->sx) + pfc.mult(gpk->w, (-1) * sigma0->c), sigma0->T) * pfc.power(rt2, sigma0->sf) * pfc.power(rt3, sigma0->sb) * pfc.power(rt4, sigma0->sa) * pfc.power(rt1, sigma0->c);
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
    revokerCheckPRL(pRL, &sigma0->B, &sigma0->K);
    revokerCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K);

    cout << "Verification succeeds! " << endl;
}