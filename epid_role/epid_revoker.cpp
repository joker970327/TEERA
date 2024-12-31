#include "epid_revoker.h"

GT rt1,rt2,rt3,rt4;
SRL *sRL;
PRL *pRL;
PFC *revokerPFC = &pfc;

void setPRL(Public_PRL *pPRL){    
    PRLNode *p = pRL->head;
    int c;
    if(p != nullptr){
        c = 1;
    }else{return;}
    while(p->next){
        c++;
        p = p->next;
    }
    p = pRL->head;
    delete(pPRL->f);
    pPRL->f = new Big[c];
    for(int i=0;i<c;i++){
        pPRL->f[i] = p->f;
        p = p->next;
    }
    pPRL->cnt = c;
}

void setSRL(Public_SRL *pSRL){
    BK *q = sRL->head;
    int c;
    if(q != nullptr){
        c = 1;
    }else{return;}
    while(q->next){
        c++;
        q = q->next;
    }
    q = sRL->head;
    delete(pSRL->sRLNode);
    pSRL->sRLNode = new Public_SRLNode[c];
    for(int i=0;i<c;i++){
        pSRL->sRLNode[i].B = q->B;
        pSRL->sRLNode[i].K = q->K;
    }
    pSRL->cnt = c;
}

void revokerPreCom(Public_PRL *pPRL, Public_SRL *pSRL)
{
    // revokerPFC = PFC(AES_SECURITY);
    pRL = new PRL();
    sRL = new SRL();

    revokerPFC->precomp_for_power(rt1);
    revokerPFC->precomp_for_power(rt2);
    revokerPFC->precomp_for_power(rt3);
    revokerPFC->precomp_for_power(rt4);

    setPRL(pPRL);
    setSRL(pSRL);
}

int revokerCheckPRL(Public_PRL *pRL, G3 *B, G3 *K){
    for(int i=0;i<pRL->cnt;i++){
        if(*K==revokerPFC->mult(*B,pRL->f[i])){
            cout << "pRL revoked! " << endl;
            return -1;
        }
    }
    return 0;
}

int revokerCheckSRL(GPK *gpk, char *m, Revoker_Sigmai *sigmai, G3 *B, G3 *K){
    for(int i=0;i<sigmai->cnt;i++){
        Revoker_BK_SPK *s = &(sigmai->sigmai[i]);
        G3 R = revokerPFC->mult(*B,s->sf)+revokerPFC->mult(*K,(-1) * s->c);
        G3 Ri = revokerPFC->mult(s->B,s->sf)+revokerPFC->mult(s->K,(-1)*s->c);
        revokerPFC->start_hash();
        revokerPFC->add_to_hash(gpk->p);
        revokerPFC->add_to_hash(gpk->g1);
        revokerPFC->add_to_hash(gpk->g2);
        revokerPFC->add_to_hash(gpk->g3);
        revokerPFC->add_to_hash(gpk->h1);
        revokerPFC->add_to_hash(gpk->h2);
        revokerPFC->add_to_hash(gpk->w);
        revokerPFC->add_to_hash(*B);
        revokerPFC->add_to_hash(*K);
        revokerPFC->add_to_hash(R);
        revokerPFC->add_to_hash(s->B);
        revokerPFC->add_to_hash(s->K);
        revokerPFC->add_to_hash(Ri);
        revokerPFC->add_to_hash(m);
        Big c = revokerPFC->finish_hash_to_group();
        if(c == s->c){
            cout << "sRL revoked! " << endl;
            return -1;
        }
    }
    return 0;
}

void revokerRevokePRL(GPK *gpk, Public_PRL *pPRL, Revoker_SK *sk){
    G2 wxg2 = gpk->w + revokerPFC->mult(gpk->g2, sk->x);
    G1 g1h1fh2y = -(revokerPFC->mult(gpk->h1, sk->f) + revokerPFC->mult(gpk->h2, sk->y) + gpk->g1);
    G1 *e1[2];
    G2 *e2[2];
    e1[0] = &sk->A;
    e1[1] = &g1h1fh2y;
    e2[0] = &wxg2;
    e2[1] = &gpk->g2;
    if (revokerPFC->multi_pairing(2, e2, e1) != 1)
    {
        cout << "Pairing verification failed, aborting.. " << endl;
        exit(0);
    }

    // PRLNode *tmp = (PRLNode*)malloc(sizeof(PRLNode));
    PRLNode *tmp = new PRLNode();
    tmp->f = sk->f;
    if(pRL->head==NULL){
        pRL->head = tmp;
    }else{
        pRL->tail->next = tmp;
    }
    pRL->tail = tmp;

    setPRL(pPRL);
}
int revokerRevokeSRL(GPK *gpk, Public_PRL *pPRL, Public_SRL *pSRL, char *m, Revoker_Sigma *sigma){
    if(revokerVerify(gpk,m,pPRL,sigma->sigmai,sigma->sigma0))return -1;
    // BK *tmp = (BK*)malloc(sizeof(BK));
    BK *tmp = new BK();
    tmp->B = sigma->sigma0->B;
    tmp->K = sigma->sigma0->K;
    if(sRL->head==NULL){
        sRL->head = tmp;
    }else{
        sRL->tail->next = tmp;
    }
    sRL->tail = tmp;

    setSRL(pSRL);
    return 0;
}

int revokerVerify(GPK *gpk, char *m, Public_PRL *pPRL, Revoker_Sigmai *sigmai, Revoker_Sigma0 *sigma0)
{
    // 验证sigma0的知识证明
    G3 R1 = revokerPFC->mult(sigma0->B, sigma0->sf) + revokerPFC->mult(sigma0->K, (-1) * sigma0->c);
    GT R2 = revokerPFC->pairing(revokerPFC->mult(gpk->g2, (-1) * sigma0->sx) + revokerPFC->mult(gpk->w, (-1) * sigma0->c), sigma0->T) * revokerPFC->power(rt2, sigma0->sf) * revokerPFC->power(rt3, sigma0->sb) * revokerPFC->power(rt4, sigma0->sa) * revokerPFC->power(rt1, sigma0->c);
    revokerPFC->start_hash();
    revokerPFC->add_to_hash(gpk->p);
    revokerPFC->add_to_hash(gpk->g1);
    revokerPFC->add_to_hash(gpk->g2);
    revokerPFC->add_to_hash(gpk->g3);
    revokerPFC->add_to_hash(gpk->h1);
    revokerPFC->add_to_hash(gpk->h2);
    revokerPFC->add_to_hash(gpk->w);
    revokerPFC->add_to_hash(sigma0->B);
    revokerPFC->add_to_hash(sigma0->K);
    revokerPFC->add_to_hash(sigma0->T);
    revokerPFC->add_to_hash(R1);
    revokerPFC->add_to_hash(R2);
    revokerPFC->add_to_hash(m);
    Big c = revokerPFC->finish_hash_to_group();

    if (c != sigma0->c)
    {
        cout << " Revoker verification failed, aborting.. " << endl;
        return -1;
    }
//检查pRL和sRL
    if(revokerCheckPRL(pPRL, &sigma0->B, &sigma0->K))return -1;
    if(revokerCheckSRL(gpk, m, sigmai, &sigma0->B, &sigma0->K))return -1;

    cout << "Revoker verification succeeds! " << endl;
    return 0;
}