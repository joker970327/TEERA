#include "epid_curve_BLS12383.h"
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

void hash_SRLNode_epid(Big c, Big p, G1* g1, G2* g2, G1* g3, G1* h1, G1* h2,  G2* w, G1* B, G1* K, G1* B1,G1* K1,G1* Ri, char* message){
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
    BIG_copy(tmp_Big,p);
    BIG_toBytes(order_o.val,tmp_Big);
    order_o.len+=MODBYTES;
    for(i=0;i<order_o.len;i++)shs_process(&sh,order_o.val[i]);
    
    octet g1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g1);
    G1_toOctet(&g1_o,&tmp_G1,false);
    for(i=0;i<g1_o.len;i++)shs_process(&sh,g1_o.val[i]);

    octet g2_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,g2);
    G2_toOctet(&g2_o,&tmp_G2,false);
    for(i=0;i<g2_o.len;i++)shs_process(&sh,g2_o.val[i]);

    octet g3_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g3);
    G1_toOctet(&g3_o,&tmp_G1,false);
    for(i=0;i<g3_o.len;i++)shs_process(&sh,g3_o.val[i]);

    octet h1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h1);
    G1_toOctet(&h1_o,&tmp_G1,false);
    for(i=0;i<h1_o.len;i++)shs_process(&sh,h1_o.val[i]);

    octet h2_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h2);
    G1_toOctet(&h2_o,&tmp_G1,true);
    for(i=0;i<h2_o.len;i++)shs_process(&sh,h2_o.val[i]);

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

    octet B1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,B1);
    G1_toOctet(&B1_o,&tmp_G1,false);
    for(i=0;i<B1_o.len;i++)shs_process(&sh,B1_o.val[i]);

    octet K1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,K1);
    G1_toOctet(&K1_o,&tmp_G1,false);
    for(i=0;i<K1_o.len;i++)shs_process(&sh,K1_o.val[i]);

    octet Ri_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,Ri);
    G1_toOctet(&Ri_o,&tmp_G1,false);
    for(i=0;i<Ri_o.len;i++)shs_process(&sh,Ri_o.val[i]);

    octet message_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,message);
    BIG_toBytes(&(message_o.val[0]),tmp_Big);
    message_o.len+=MODBYTES;
    for(i=0;i<message_o.len;i++)shs_process(&sh,message_o.val[i]);

    shs_hash(&sh,hh);
    BIG_fromBytes(c,hh);
}

void hash_comm_epid(Big c, Big p, G1* g1, G2* g2, G1* g3, G1* h1, G1* h2,  G2* w, G1* C, G1* PoC){
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
    BIG_copy(tmp_Big,p);
    BIG_toBytes(order_o.val,tmp_Big);
    order_o.len+=MODBYTES;
    for(i=0;i<order_o.len;i++)shs_process(&sh,order_o.val[i]);
    
    octet g1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g1);
    G1_toOctet(&g1_o,&tmp_G1,false);
    for(i=0;i<g1_o.len;i++)shs_process(&sh,g1_o.val[i]);

    octet g2_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,g2);
    G2_toOctet(&g2_o,&tmp_G2,false);
    for(i=0;i<g2_o.len;i++)shs_process(&sh,g2_o.val[i]);

    octet g3_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g3);
    G1_toOctet(&g3_o,&tmp_G1,false);
    for(i=0;i<g3_o.len;i++)shs_process(&sh,g3_o.val[i]);

    octet h1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h1);
    G1_toOctet(&h1_o,&tmp_G1,false);
    for(i=0;i<h1_o.len;i++)shs_process(&sh,h1_o.val[i]);

    octet h2_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h2);
    G1_toOctet(&h2_o,&tmp_G1,true);
    for(i=0;i<h2_o.len;i++)shs_process(&sh,h2_o.val[i]);

    octet w_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,w);
    G2_toOctet(&w_o,&tmp_G2,false);
    for(i=0;i<w_o.len;i++)shs_process(&sh,w_o.val[i]);

    octet C_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,C);
    G1_toOctet(&C_o,&tmp_G1,false);
    for(i=0;i<C_o.len;i++)shs_process(&sh,C_o.val[i]);

    octet PoC_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,PoC);
    G1_toOctet(&PoC_o,&tmp_G1,false);
    for(i=0;i<PoC_o.len;i++)shs_process(&sh,PoC_o.val[i]);

    shs_hash(&sh,hh);
    BIG_fromBytes(c,hh);
}

void hash_sigma_epid(Big c, Big p, G1* g1, G2* g2, G1* g3, G1* h1, G1* h2,  G2* w, G1* B, G1* K, G1* T, G1* R1,GT* R2,char* message){
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
    Big tmp_Big;
    GT tmp_GT;


    octet order_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,p);
    BIG_toBytes(order_o.val,tmp_Big);
    order_o.len+=MODBYTES;
    for(i=0;i<order_o.len;i++)shs_process(&sh,order_o.val[i]);
    
    octet g1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g1);
    G1_toOctet(&g1_o,&tmp_G1,false);
    for(i=0;i<g1_o.len;i++)shs_process(&sh,g1_o.val[i]);

    octet g2_o={0,sizeof(g2_s),g2_s};
    G2_copy(&tmp_G2,g2);
    G2_toOctet(&g2_o,&tmp_G2,false);
    for(i=0;i<g2_o.len;i++)shs_process(&sh,g2_o.val[i]);

    octet g3_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,g3);
    G1_toOctet(&g3_o,&tmp_G1,false);
    for(i=0;i<g3_o.len;i++)shs_process(&sh,g3_o.val[i]);

    octet h1_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h1);
    G1_toOctet(&h1_o,&tmp_G1,false);
    for(i=0;i<h1_o.len;i++)shs_process(&sh,h1_o.val[i]);

    octet h2_o={0,sizeof(g1_s),g1_s};
    G1_copy(&tmp_G1,h2);
    G1_toOctet(&h2_o,&tmp_G1,true);
    for(i=0;i<h2_o.len;i++)shs_process(&sh,h2_o.val[i]);

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

    octet message_o={0,sizeof(big_s),big_s};
    BIG_copy(tmp_Big,message);
    BIG_toBytes(&(message_o.val[0]),tmp_Big);
    message_o.len+=MODBYTES;
    for(i=0;i<message_o.len;i++)shs_process(&sh,message_o.val[i]);

    shs_hash(&sh,hh);
    BIG_fromBytes(c,hh);
}

void display_G1(G1 *g1){
    char g1_s[2*MODBYTES+1];
    octet o={0,sizeof(g1_s),g1_s};
    // ECP2_BLS12383_affine(g1);
    G1 tmp;
    G1_copy(&tmp,g1);
    G1_toOctet(&o,&tmp,false);
    printf("        type: G1, size: %d\n        ",o.len);
    OCT_output(&o);
}

void display_G2(G2 *g2){
    char g2_s[4*MODBYTES+1];
    octet o={0,sizeof(g2_s),g2_s};
    // ECP2_BLS12383_affine(g2);
    G2 tmp;
    G2_copy(&tmp,g2);
    G2_toOctet(&o,&tmp,false);
    printf("        type: G2, size: %d\n        ",o.len);
    OCT_output(&o);
}

void display_GT(GT *gt){
    char gt_s[12*MODBYTES+1];
    octet o={0,sizeof(gt_s),gt_s};
    // FP12_BLS12383_norm(gt);
    GT tmp;
    GT_copy(&tmp,gt);
    GT_toOctet(&o,&tmp);
    printf("        type: GT, size: %d\n        ",o.len);
    OCT_output(&o);
}

void display_Big(Big b){
    // char *a;
    // BIG_toBytes(a,b);
    char big_s[MODBYTES];
    octet o={0,sizeof(big_s),big_s};
    // BIG_384_58_norm(b);
    BIG_toBytes(&(o.val[0]),b);
    o.len+=MODBYTES;
    printf("        type: Big, size: %d\n        ",o.len);
    OCT_output(&o);
}