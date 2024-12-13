#include "epid_platform.h"

GT pt1,pt2,pt3,pt4;
SK *sk;//sk
Big y_1;

void platformPreCom()
{
    pfc.precomp_for_power(pt1);
    pfc.precomp_for_power(pt2);
    pfc.precomp_for_power(pt3);
    pfc.precomp_for_power(pt4);
}

CommC *platformJoin_1(GPK *gpk)
{
    Big f;
    pfc.random(f);
    pfc.random(y_1);

    // C的知识证明
    // CommC *commC = (CommC *)malloc(sizeof(CommC));
    CommC *commC = new CommC();
    commC->C = pfc.mult(gpk->h1, f) + pfc.mult(gpk->h2, y_1);
    Big rf, ry1, c;
    G1 PoC;
    pfc.random(rf);
    pfc.random(ry1);
    PoC = pfc.mult(gpk->h1, rf) + pfc.mult(gpk->h2, ry1);
    // 计算c的哈希值，暂时只用一些参数，需要与证明的对应
    pfc.start_hash();
    pfc.add_to_hash(gpk->p);
    pfc.add_to_hash(gpk->h1);
    pfc.add_to_hash(gpk->h2);
    pfc.add_to_hash(commC->C);
    pfc.add_to_hash(PoC);
    c = pfc.finish_hash_to_group();

    // sk = (SK *)malloc(sizeof(SK));
    sk = new SK();
    sk->f = f;

    commC->sf = (rf + modmult(c, f, gpk->p)) % gpk->p;
    commC->sy1 = (ry1 + modmult(c, y_1, gpk->p)) % gpk->p;
    commC->c = c;

    return commC;
}

PPK *platformJoin_3(GPK *gpk, CRE *cre)
{
    Big y = (y_1 + cre->y2) % gpk->p;
    // pairing验证
    G2 wxg2 = gpk->w + pfc.mult(gpk->g2, cre->x);
    G1 g1h1fh2y = -(pfc.mult(gpk->h1, sk->f) + pfc.mult(gpk->h2, y) + gpk->g1);
    G1 *e1[2];
    G2 *e2[2];
    e1[0] = &cre->A;
    e1[1] = &g1h1fh2y;
    e2[0] = &wxg2;
    e2[1] = &gpk->g2;
    if (pfc.multi_pairing(2, e2, e1) != 1)
    {
        cout << "Pairing verification failed, aborting.. " << endl;
        exit(0);
    }

    sk->A = cre->A;
    sk->x = cre->x;
    sk->y = y;

    // PPK *pk = (PPK *)malloc(sizeof(PPK));
    PPK *pk = new PPK();
    pk->A = cre->A;
    pk->x = cre->x;
    pk->y = y;

    return pk;
}

Sigma *platformSign(GPK *gpk, char *m, SRL *sRL)
{
    G3 B, K, R1;
    G1 T;
    GT R2;
    Big a, b;

    pfc.random(B);
    K = pfc.mult(B, sk->f);
    pfc.random(a);
    b = sk->y + modmult(a, sk->x, gpk->p) % gpk->p;
    T = sk->A + pfc.mult(gpk->h2, a);

    // 生成sigma0的知识证明
    Big rx, rf, ra, rb, c;
    Big sx, sf, sa, sb;
    pfc.random(rx);
    pfc.random(rf);
    pfc.random(ra);
    pfc.random(rb);
    R1 = pfc.mult(B, rf);
    R2 = pfc.power(pfc.pairing(gpk->g2, sk->A), -rx) * pfc.power(pt2, rf) * pfc.power(pt3, rb - modmult(a, rx, gpk->p) % gpk->p) * pfc.power(pt4, ra);
    pfc.start_hash();
    pfc.add_to_hash(gpk->p);
    pfc.add_to_hash(gpk->g1);
    pfc.add_to_hash(gpk->g2);
    pfc.add_to_hash(gpk->g3);
    pfc.add_to_hash(gpk->h1);
    pfc.add_to_hash(gpk->h2);
    pfc.add_to_hash(gpk->w);
    pfc.add_to_hash(B);
    pfc.add_to_hash(K);
    pfc.add_to_hash(T);
    pfc.add_to_hash(R1);
    pfc.add_to_hash(R2);
    pfc.add_to_hash(m);
    c = pfc.finish_hash_to_group();
    sx = (rx + modmult(c, sk->x, gpk->p)) % gpk->p;
    sa = (ra + modmult(c, a, gpk->p)) % gpk->p;
    sb = (rb + modmult(c, b, gpk->p)) % gpk->p;
    sf = (rf + modmult(c, sk->f, gpk->p)) % gpk->p;

    // Sigma0 *sigma0 = (Sigma0 *)malloc(sizeof(Sigma0));
    Sigma0 *sigma0 = new Sigma0();

    sigma0->B = B;
    sigma0->K = K;
    sigma0->c = c;
    sigma0->T = T;
    sigma0->sa = sa;
    sigma0->sx = sx;
    sigma0->sb = sb;
    sigma0->sf = sf;

    // 生成sigmai

    BK *s = sRL->head;

    // sigmai涉及到不等式进行知识证明
    // 暂时将每个不等式作为一个单独的知识证明，sigma0中已经证明了B=K^f
    // 那么sigmai就证明Ki=Bi^f，但是需要每一个都证明失败
    // Sigmai *sigmai = (Sigmai *)malloc(sizeof(Sigmai));
    Sigmai *sigmai = new Sigmai();

    while(s!=NULL)
    {
        G3 R = pfc.mult(B,rf);
        G3 Ri = pfc.mult(s->B,rf);
        pfc.start_hash();
        pfc.add_to_hash(gpk->p);
        pfc.add_to_hash(gpk->g1);
        pfc.add_to_hash(gpk->g2);
        pfc.add_to_hash(gpk->g3);
        pfc.add_to_hash(gpk->h1);
        pfc.add_to_hash(gpk->h2);
        pfc.add_to_hash(gpk->w);
        pfc.add_to_hash(B);
        pfc.add_to_hash(K);
        pfc.add_to_hash(R);
        pfc.add_to_hash(s->B);
        pfc.add_to_hash(s->K);
        pfc.add_to_hash(Ri);
        pfc.add_to_hash(m);
        c = pfc.finish_hash_to_group();

        sf = (rf + modmult(c, sk->f, gpk->p))%gpk->p;

        // BK_SPK *tmpSPK = (BK_SPK*)malloc(sizeof(BK_SPK));
        BK_SPK *tmpSPK = new BK_SPK();

        tmpSPK->B = s->B;
        tmpSPK->K = s->K;
        tmpSPK->c = c;
        tmpSPK->sf = sf;

        if(sigmai->head==NULL){
            sigmai->head = tmpSPK;
        }
        else{
            sigmai->tail->next = tmpSPK;
        }
        sigmai->tail = tmpSPK;

        s = s->next;
    }
    pfc.add_to_hash(m);

    // Sigma *sigma = (Sigma *)malloc(sizeof(Sigma));
    Sigma *sigma = new Sigma();
    sigma->sigma0 = sigma0;
    sigma->sigmai = sigmai;


    // 生成知识证明:BK用于sRL
    //  Big rbkf,cbk;
    //  Big sbkf;
    //  G3 PoK;
    //  pfc.random(rbkf);
    //  PoK=pfc.mult(B,rbkf);
    //  pfc.start_hash();
    //  pfc.add_to_hash(gpk->p);pfc.add_to_hash(gpk->g1);pfc.add_to_hash(gpk->g2);pfc.add_to_hash(gpk->g3);
    //  pfc.add_to_hash(gpk->h1);pfc.add_to_hash(gpk->h2);pfc.add_to_hash(gpk->w);
    //  pfc.add_to_hash(B);pfc.add_to_hash(K);pfc.add_to_hash(PoK);
    //  cbk = pfc.finish_hash_to_group();
    //  sbkf = (rbkf+modmult(cbk,f,gpk->p))%gpk->p;

    // BK *bk = (BK*)malloc(sizeof(BK));
    // bk->B = B;
    // bk->K = K;
    // bk->c = cbk;
    // bk->sf = sbkf;

    return sigma;
}