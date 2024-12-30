#include "epid_platform.h"

GT pt1,pt2,pt3,pt4;
SK *sk;//sk
Big y_1;

PFC *platformPFC=&pfc;

void platformPreCom()
{
    // platformPFC = PFC(AES_SECURITY);
    platformPFC->precomp_for_power(pt1);
    platformPFC->precomp_for_power(pt2);
    platformPFC->precomp_for_power(pt3);
    platformPFC->precomp_for_power(pt4);
}

void platformJoin_1(GPK *gpk, Platform_CommC* commC)
{
    Big f;
    platformPFC->random(f);
    platformPFC->random(y_1);

    // C的知识证明
    // CommC *commC = (CommC *)malloc(sizeof(CommC));
    commC->C = platformPFC->mult(gpk->h1, f) + platformPFC->mult(gpk->h2, y_1);
    Big rf, ry1, c;
    G1 PoC;
    platformPFC->random(rf);
    platformPFC->random(ry1);
    PoC = platformPFC->mult(gpk->h1, rf) + platformPFC->mult(gpk->h2, ry1);
    // 计算c的哈希值，暂时只用一些参数，需要与证明的对应
    platformPFC->start_hash();
    platformPFC->add_to_hash(gpk->p);
    platformPFC->add_to_hash(gpk->h1);
    platformPFC->add_to_hash(gpk->h2);
    platformPFC->add_to_hash(commC->C);
    platformPFC->add_to_hash(PoC);
    c = platformPFC->finish_hash_to_group();

    sk = new SK();
    sk->f = f;

    commC->sf = (rf + modmult(c, f, gpk->p)) % gpk->p;
    commC->sy1 = (ry1 + modmult(c, y_1, gpk->p)) % gpk->p;
    commC->c = c;
}

int platformJoin_3(GPK *gpk, Platform_CRE *cre, PPK *pk)
{
    Big y = (y_1 + cre->y2) % gpk->p;
    // pairing验证
    G2 wxg2 = gpk->w + platformPFC->mult(gpk->g2, cre->x);
    G1 g1h1fh2y = -(platformPFC->mult(gpk->h1, sk->f) + platformPFC->mult(gpk->h2, y) + gpk->g1);
    G1 *e1[2];
    G2 *e2[2];
    e1[0] = &cre->A;
    e1[1] = &g1h1fh2y;
    e2[0] = &wxg2;
    e2[1] = &gpk->g2;
    if (platformPFC->multi_pairing(2, e2, e1) != 1)
    {
        cout << "Pairing verification failed, aborting.. " << endl;
        return -1;
    }

    sk->A = cre->A;
    sk->x = cre->x;
    sk->y = y;

    pk->A = cre->A;
    pk->x = cre->x;
    pk->y = y;

    return 0;
}

void platformSign(GPK *gpk, char *m, Public_SRL *sRL, Platform_Sigma* sigma)
{
    G3 B, K, R1;
    G1 T;
    GT R2;
    Big a, b;

    platformPFC->random(B);
    K = platformPFC->mult(B, sk->f);
    platformPFC->random(a);
    b = sk->y + modmult(a, sk->x, gpk->p) % gpk->p;
    T = sk->A + platformPFC->mult(gpk->h2, a);

    // 生成sigma0的知识证明
    Big rx, rf, ra, rb, c;
    Big sx, sf, sa, sb;
    platformPFC->random(rx);
    platformPFC->random(rf);
    platformPFC->random(ra);
    platformPFC->random(rb);
    R1 = platformPFC->mult(B, rf);
    R2 = platformPFC->power(platformPFC->pairing(gpk->g2, sk->A), -rx) * platformPFC->power(pt2, rf) * platformPFC->power(pt3, rb - modmult(a, rx, gpk->p) % gpk->p) * platformPFC->power(pt4, ra);
    platformPFC->start_hash();
    platformPFC->add_to_hash(gpk->p);
    platformPFC->add_to_hash(gpk->g1);
    platformPFC->add_to_hash(gpk->g2);
    platformPFC->add_to_hash(gpk->g3);
    platformPFC->add_to_hash(gpk->h1);
    platformPFC->add_to_hash(gpk->h2);
    platformPFC->add_to_hash(gpk->w);
    platformPFC->add_to_hash(B);
    platformPFC->add_to_hash(K);
    platformPFC->add_to_hash(T);
    platformPFC->add_to_hash(R1);
    platformPFC->add_to_hash(R2);
    platformPFC->add_to_hash(m);
    c = platformPFC->finish_hash_to_group();
    sx = (rx + modmult(c, sk->x, gpk->p)) % gpk->p;
    sa = (ra + modmult(c, a, gpk->p)) % gpk->p;
    sb = (rb + modmult(c, b, gpk->p)) % gpk->p;
    sf = (rf + modmult(c, sk->f, gpk->p)) % gpk->p;


    sigma->sigma0->B = B;
    sigma->sigma0->K = K;
    sigma->sigma0->c = c;
    sigma->sigma0->T = T;
    sigma->sigma0->sa = sa;
    sigma->sigma0->sx = sx;
    sigma->sigma0->sb = sb;
    sigma->sigma0->sf = sf;

    // 生成sigmai

    Public_SRLNode *s;

    // sigmai涉及到不等式进行知识证明
    // 暂时将每个不等式作为一个单独的知识证明，sigma0中已经证明了B=K^f
    // 那么sigmai就证明Ki=Bi^f，但是需要每一个都证明失败
    // Sigmai *sigmai = (Sigmai *)malloc(sizeof(Sigmai));

    for(int i=0;i<sRL->cnt;i++)
    {
        s = &(sRL->sRLNode[i]);
        G3 R = platformPFC->mult(B,rf);
        G3 Ri = platformPFC->mult(s->B,rf);
        platformPFC->start_hash();
        platformPFC->add_to_hash(gpk->p);
        platformPFC->add_to_hash(gpk->g1);
        platformPFC->add_to_hash(gpk->g2);
        platformPFC->add_to_hash(gpk->g3);
        platformPFC->add_to_hash(gpk->h1);
        platformPFC->add_to_hash(gpk->h2);
        platformPFC->add_to_hash(gpk->w);
        platformPFC->add_to_hash(B);
        platformPFC->add_to_hash(K);
        platformPFC->add_to_hash(R);
        platformPFC->add_to_hash(s->B);
        platformPFC->add_to_hash(s->K);
        platformPFC->add_to_hash(Ri);
        platformPFC->add_to_hash(m);
        c = platformPFC->finish_hash_to_group();

        sf = (rf + modmult(c, sk->f, gpk->p))%gpk->p;

        sigma->sigmai->sigmai[i].B = s->B;
        sigma->sigmai->sigmai[i].K = s->K;
        sigma->sigmai->sigmai[i].c = c;
        sigma->sigmai->sigmai[i].sf = sf;

    }

    // 生成知识证明:BK用于sRL
    //  Big rbkf,cbk;
    //  Big sbkf;
    //  G3 PoK;
    //  platformPFC->random(rbkf);
    //  PoK=platformPFC->mult(B,rbkf);
    //  platformPFC->start_hash();
    //  platformPFC->add_to_hash(gpk->p);platformPFC->add_to_hash(gpk->g1);platformPFC->add_to_hash(gpk->g2);platformPFC->add_to_hash(gpk->g3);
    //  platformPFC->add_to_hash(gpk->h1);platformPFC->add_to_hash(gpk->h2);platformPFC->add_to_hash(gpk->w);
    //  platformPFC->add_to_hash(B);platformPFC->add_to_hash(K);platformPFC->add_to_hash(PoK);
    //  cbk = platformPFC->finish_hash_to_group();
    //  sbkf = (rbkf+modmult(cbk,f,gpk->p))%gpk->p;

    // BK *bk = (BK*)malloc(sizeof(BK));
    // bk->B = B;
    // bk->K = K;
    // bk->c = cbk;
    // bk->sf = sbkf;

}

SK* platformLeakSK_Test(){
    return sk;
}