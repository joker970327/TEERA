#include "RA_curve.h"
csprng* RNG=NULL;
FP4 G2_TAB[G2_TABLE];  // space for precomputation on fixed G2 parameter
hash SH;
void initiate(){
    int i,res;
    char pr[10];
    unsigned long ran;

    time((time_t *)&ran);
    pr[0] = ran;
    pr[1] = ran >> 8;
    pr[2] = ran >> 16;
    pr[3] = ran >> 24;
    for (i = 4; i < 10; i++) pr[i] = i;
    RNG = (csprng *)malloc(sizeof(csprng));
    RAND_seed(RNG, 10, pr);

// RA: for multi_pairing 初始化和预计算
    // res = BLS_INIT();
    // if (res == BLS_FAIL)
    // {
    //     printf("Failed to initialize\n");
    //     return res;
    // }
}

void order(Big order){
    BIG_rcopy(order,CURVE_Order);
}

void random_G1_generator(G1 *g){
    G1_generator(g);
}

void random_G2_generator(G2 *g){
    G2_generator(g);
}

void random_G1(G1 *h){
    FP tmp;
    FP_rand(&tmp,RNG);
    G1_map2point(h,&tmp);
    G1_cfp(h);
}

void random_G2(G2 *h){
    FP2 tmp;
    FP2_rand(&tmp,RNG);
    G2_map2point(h,&tmp);
    G2_cfp(h);
}

// RA: 参考benchtest_all.c
void random_Big(Big b){
    BIG_randtrunc(b, CURVE_Order, 2 * CURVE_SECURITY, RNG);
}

void pair_mult_G1(G1* result, G1* a, Big b){
    G1_copy(result, a);
    PAIR_G1mul(result, b);
}

void pair_mult_G2(G2* result, G2* a, Big b){
    G2_copy(result, a);
    PAIR_G2mul(result, b);
}

void pairing(GT* gt, G2* g2, G1* g1){
    PAIR_ate(gt, g2, g1);
    PAIR_fexp(gt);
    // PAIR_GTpow(gt, CURVE_Order);
}

// RA-TODO: - implement multi_pairing
// RA: 目前是根据 pair.c文件中的 multi-pairing部分的注释写的内容
// 以下来自 bls_BLS12383.c/BLS_BLS12383_CORE_VERIFY()
/*
// Use new multi-pairing mechanism
FP12_BLS12383 r[ATE_BITS_BLS12383];
PAIR_BLS12383_initmp(r);
PAIR_BLS12383_another_pc(r, G2_TAB, &D);
PAIR_BLS12383_another(r, &PK, &HM);
PAIR_BLS12383_miller(&v, r);
*/
void multi_pairing(int n, GT* gt, G2* g2, G1* g1){
    GT r[ATE_BITS];
    PAIR_initmp(r);
    PAIR_another(r, g2, g1);
    PAIR_BLS12383_miller(&gt, r);
}

void H1(Big h, char *string){
    Big p;
    unsigned char s[HASH_LEN];
    int i,j;
    hash sh;

    shs_init(&sh);

    for(i=0;;i++){
        if(string[i]==0)break;
        shs_process(&sh,string[i]);
    }
    shs_hash(&sh,(char *)s);

// RA: miracl中使用get_modulus()，但是miracl-core没有这个函数
// miracl中的get_modulus()看起来像是一个提前设置好的量
// 在Big_randtrunc中，将order阶数作为了模数，即mod p
// BL10-EPID论文中，所有的模数都是阶数p，所以此处使用order
    order(p);
    BIG_one(h);
    j=0;i=1;
    for(;;){
        modmult(h,h,HASH_NUM,p);
        if(j==HASH_LEN){
            modadd(h,h,i++,p);
            j=0;
        }
        else modadd(h,h,s[j++],p);
        if(h>=p)break;
    }
    BIG_mod(h,p);
    return h;
}

void hash_and_map(G1* w,char *ID){
    Big x0;
    FP fp;
    FP_fromBytes(&fp,ID);
    G1_map2point(w,&fp);
    G1_cfp(w);
}

void start_hash(hash* sh){
    shs_init(sh);
}

void finish_hash_to_group(Big b, hash* sh){
    char s[HASH_LEN];
    shs_hash(sh,s);
    BIG_fromBytes(b,s);
    BIG_mod(b,CURVE_Order);
}

// RA: miracl/bn_pair.cpp中GT内容为ZZn12{ZZn4 a,b,c}，ZZn4{zzn4 fn}
/* miracl中add_to_hash 
    将x.g(ZZn12).a(ZZn4).fn(zzn4).a(ZZn2).x(ZZn)，
                                       ...y(ZZn)，
                               ...b(ZZn2).x(ZZn)，
                               ...b(ZZn2).y(ZZn)
    分别转为Big，然后循环（模运算以及shs256_process）
*/
void add_to_hash_GT_FP12(GT* v, hash* sh){
    FP4 u;
    FP2 h,l;
    Big a;
    FP xx[6];

    int i,j,m;
    FP4_copy(&u,&v->a);
    FP2_copy(&l,&u.a);
    FP2_copy(&h,&u.b);
    FP_copy(&xx[0],&l.a);
    FP_copy(&xx[1],&l.b);
    FP_copy(&xx[2],&h.a);
    FP_copy(&xx[3],&h.b);
    // u = v->a;
    // l = u.a;
    // h = u.b;
    // xx[0] = l.a;
    // xx[1] = l.b;
    // xx[2] = h.a;
    // xx[3] = h.b;

    for (i=0;i<4;i++)
    {
        BIG_copy(a,xx[i].g);
        while (a>0)
        {
            BIG_ctdmod(m,a,HASH_NUM,BIG_nbits(HASH_NUM));
            shs_process(sh,m);
            BIG_ctddiv(a,a,HASH_NUM,BIG_nbits(HASH_NUM));
        }
    }

}

void add_to_hash_G1(G1* x, hash* sh){
    Big a,X,Y;
	int i,m;

	// x.g.get(X,Y);
    G1_get(&X,&Y,x);
	// a=X;
    BIG_copy(a,X);
    while (a>0)
    {
        BIG_ctdmod(m,a,HASH_NUM,BIG_nbits(HASH_NUM));
        // m=a%256;
        shs_process(sh,m);
        // a/=256;
        BIG_ctddiv(a,a,HASH_NUM,BIG_nbits(HASH_NUM));
    }
	// a=Y;
    BIG_copy(a,Y);
    while (a>0)
    {
        BIG_ctdmod(m,a,HASH_NUM,BIG_nbits(HASH_NUM));
        shs_process(sh,m);
        BIG_ctddiv(a,a,HASH_NUM,BIG_nbits(HASH_NUM));
    }
}

void add_to_hash_G2(G2* v,hash* sh){
    FP2 X,Y;
	Big a;
	FP xx[4];

	int i,m;

    G2_get(&X,&Y,v);
	// v.get(X,Y);
    FP_copy(&xx[0],&X.a);
    FP_copy(&xx[1],&X.b);
    FP_copy(&xx[2],&Y.a);
    FP_copy(&xx[3],&Y.b);
	// X.get(xx[0],xx[1]);
	// Y.get(xx[2],xx[3]);
	for (i=0;i<4;i++)
    {
        // a=(Big)xx[i];
        BIG_copy(a,xx[i].g);
        while (a>0)
        {
            BIG_ctdmod(m,a,HASH_NUM,BIG_nbits(HASH_NUM));
            shs_process(sh,m);
            BIG_ctddiv(a,a,HASH_NUM,BIG_nbits(HASH_NUM));
        }
    }
}

void add_to_hash_Big(Big b,hash* sh){
    int m;
	Big a;
    BIG_copy(a,b);
    while (a>0)
    {
        BIG_ctdmod(m,a,HASH_NUM,BIG_nbits(HASH_NUM));
        shs_process(sh,m);
        BIG_ctddiv(a,a,HASH_NUM,BIG_nbits(HASH_NUM));
    }
}

void add_to_hash_char(char* x,hash* sh){
    int i=0;
	while (x[i]!=0)
	{
        shs_process(sh,x[i]);
		i++;
	}
}

void pair_power_GT(GT* result, GT* a, Big b){
    GT_copy(result,a);
    PAIR_GTpow(result,b);
}

bool member(GT* gt){
    return PAIR_GTmember(gt);
}


void hash_Join_comm(Big c, Big order, G1* g1, G1* h1, G1* h2, 
    G2* g2, G2* w, Big ni, G1* F, G1* R){

    hash sh;
    shs_init(&sh);

    int i=0;
    char hh[MODBYTES]={0};
    char big_s[MODBYTES];
    char g1_s[2*MODBYTES+1];
    char g2_s[4*MODBYTES+1];

    G1 tmp_G1;
    G2 tmp_G2;
    Big tmp_Big;


    octet order_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,order);
    BIG_toBytes(order_o.val,tmp_Big);
    order_o.len+=MODBYTES;
    for(i=0;i<order_o.len;i++)shs_process(&sh,order_o.val[i]);
    
    octet g1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g1);
    G1_toOctet(&g1_o,&tmp_G1,false);
    for(i=0;i<g1_o.len;i++)shs_process(&sh,g1_o.val[i]);

    octet h1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h1);
    G1_toOctet(&h1_o,&tmp_G1,false);
    for(i=0;i<h1_o.len;i++)shs_process(&sh,h1_o.val[i]);

    octet h2_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h2);
    G1_toOctet(&h2_o,&tmp_G1,true);
    for(i=0;i<h2_o.len;i++)shs_process(&sh,h2_o.val[i]);

    octet g2_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,g2);
    G2_toOctet(&g2_o,&tmp_G2,false);
    for(i=0;i<g2_o.len;i++)shs_process(&sh,g2_o.val[i]);

    octet w_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,w);
    G2_toOctet(&w_o,&tmp_G2,false);
    for(i=0;i<w_o.len;i++)shs_process(&sh,w_o.val[i]);

    octet ni_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,ni);
    BIG_toBytes(ni_o.val,tmp_Big);
    ni_o.len+=MODBYTES;
    for(i=0;i<ni_o.len;i++)shs_process(&sh,ni_o.val[i]);

    octet F_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,F);
    G1_toOctet(&F_o,&tmp_G1,false);
    for(i=0;i<F_o.len;i++)shs_process(&sh,F_o.val[i]);

    octet R_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,R);
    G1_toOctet(&R_o,&tmp_G1,false);
    for(i=0;i<R_o.len;i++)shs_process(&sh,R_o.val[i]);

    shs_hash(&sh,hh);
    BIG_fromBytes(c,hh);
}

void hash_Sign_comm(Big c, Big order, G1* g1, G1* h1, G1* h2, 
    G2* g2, G2* w, G1* B, G1* K, G1* T, G1* R1, GT* R2, Big nv){

    hash sh;
    shs_init(&sh);
    int i=0;
    char hh[MODBYTES]={0};
    char big_s[MODBYTES];
    char g1_s[2*MODBYTES+1];
    char g2_s[4*MODBYTES+1];
    char gt_s[12*MODBYTES+1];

    G1 tmp_G1;
    G2 tmp_G2;
    GT tmp_GT;
    Big tmp_Big;

    octet order_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,order);
    BIG_toBytes(&(order_o.val[0]),tmp_Big);
    order_o.len+=MODBYTES;
    for(i=0;i<order_o.len;i++)shs_process(&sh,order_o.val[i]);
    
    octet g1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g1);
    G1_toOctet(&g1_o,&tmp_G1,false);
    for(i=0;i<g1_o.len;i++)shs_process(&sh,g1_o.val[i]);

    octet h1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h1);
    G1_toOctet(&h1_o,&tmp_G1,false);
    for(i=0;i<h1_o.len;i++)shs_process(&sh,h1_o.val[i]);
    
    octet h2_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h2);
    G1_toOctet(&h2_o,&tmp_G1,true);
    for(i=0;i<h2_o.len;i++)shs_process(&sh,h2_o.val[i]);

    octet g2_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,g2);
    G2_toOctet(&g2_o,&tmp_G2,false);
    for(i=0;i<g2_o.len;i++)shs_process(&sh,g2_o.val[i]);

    octet w_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,w);
    G2_toOctet(&w_o,&tmp_G2,false);
    for(i=0;i<w_o.len;i++)shs_process(&sh,w_o.val[i]);

    octet B_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,B);
    G1_toOctet(&B_o,&tmp_G1,false);
    for(i=0;i<B_o.len;i++)shs_process(&sh,B_o.val[i]);
 
    octet K_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,K);
    G1_toOctet(&K_o,&tmp_G1,false);
    for(i=0;i<K_o.len;i++)shs_process(&sh,K_o.val[i]);

    octet T_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,T);
    G1_toOctet(&T_o,&tmp_G1,false);
    for(i=0;i<T_o.len;i++)shs_process(&sh,T_o.val[i]);
  
    octet R1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,R1);
    G1_toOctet(&R1_o,&tmp_G1,false);
    for(i=0;i<R1_o.len;i++)shs_process(&sh,R1_o.val[i]);

    octet R2_o={0,sizeof(gt_s),gt_s};
    GT_copy(&tmp_GT,R2);
    GT_toOctet(&R2_o,&tmp_GT);
    for(i=0;i<R2_o.len;i++)shs_process(&sh,R2_o.val[i]);

    octet nv_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,nv);
    BIG_toBytes(&nv_o.val[0],tmp_Big);
    nv_o.len+=MODBYTES;
    for(i=0;i<nv_o.len;i++)shs_process(&sh,nv_o.val[i]);

    shs_hash(&sh,hh);
    BIG_fromBytes(c,hh);
}

void hash_Sign_plus(Big c, Big ch, Big nt, char* message){
    hash sh;
    shs_init(&sh);
    int i=0;
    char hh[MODBYTES]={0};

    char big_s[MODBYTES];

    Big tmp_Big;

    octet ch_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,ch);
    BIG_toBytes(&(ch_o.val[0]),tmp_Big);
    ch_o.len+=MODBYTES;
    for(i=0;i<ch_o.len;i++)shs_process(&sh,ch_o.val[i]);

    octet nt_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,nt);
    BIG_toBytes(&(nt_o.val[0]),tmp_Big);
    nt_o.len+=MODBYTES;
    for(i=0;i<nt_o.len;i++)shs_process(&sh,nt_o.val[i]);

    octet message_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,message);
    BIG_toBytes(&(message_o.val[0]),tmp_Big);
    message_o.len+=MODBYTES;
    for(i=0;i<message_o.len;i++)shs_process(&sh,message_o.val[i]);

    shs_hash(&sh,hh);
    BIG_fromBytes(c,hh);
}

void display_G1(G1 *g1){
    octet *o;
    G1_toOctet(o,g1,false);
    printf("type: G1\n");
    OCT_output(o);
}

void display_G2(G2 *g2){
    octet *o;
    G2_toOctet(o,g2,false);
    printf("type: G2\n");
    OCT_output(o);
}

void display_GT(GT *gt){
    octet *o;
    GT_toOctet(o,gt);
    printf("type: GT\n");
    OCT_output(o);
}

void display_Big(Big b){
    // char *a;
    // BIG_toBytes(a,b);
    printf("type: Big\n");
    BIG_output(b);
}