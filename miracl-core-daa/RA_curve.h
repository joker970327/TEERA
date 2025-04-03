#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef RA_CURVE_H
#define RA_CURVE_H

#define RA_PAIRING_BLS12383

#ifdef RA_PAIRING_BLS12383
#include "pair_BLS12383.h"
#include "bls_BLS12383.h"

#define G1 ECP_BLS12383
#define G2 ECP2_BLS12383
#define GT FP12_BLS12383
#define Big BIG_384_58

#define FP FP_BLS12383
#define FP4 FP4_BLS12383
#define FP2 FP2_BLS12383

#define G2_TABLE G2_TABLE_BLS12383
#define CURVE_SECURITY CURVE_SECURITY_BLS12383
#define ATE_BITS ATE_BITS_BLS12383
#define CURVE_Order CURVE_Order_BLS12383
#define MODBYTES MODBYTES_384_58
#define BFS BFS_BLS12383
#define HASH_LEN 32
#define HASH_NUM 256
#define hash hash256

#define shs_init HASH256_init
#define shs_hash HASH256_hash
#define shs_process HASH256_process

#define modmult BIG_384_58_modmul
#define modadd BIG_384_58_modadd
#define BIG_rcopy BIG_384_58_rcopy
#define BIG_copy BIG_384_58_copy
#define BIG_randtrunc BIG_384_58_randtrunc
#define BIG_fromBytes BIG_384_58_fromBytes
#define BIG_mod BIG_384_58_mod
// #define BIG_mul BIG_384_58_mul
#define BIG_ctdmod BIG_384_58_ctdmod
#define BIG_ctddiv BIG_384_58_ctddiv
#define BIG_one BIG_384_58_one
#define BIG_modneg BIG_384_58_modneg
// #define BIG_add BIG_384_58_add
#define BIG_nbits BIG_384_58_nbits
#define BIG_toBytes BIG_384_58_toBytes
#define BIG_output BIG_384_58_output
#define BIG_comp BIG_384_58_comp
#define BIG_invmodp BIG_384_58_invmodp
#define BIG_zero BIG_384_58_zero

// #define BLS_INIT BLS_BLS12383_INIT

#define G1_generator ECP_BLS12383_generator
#define G1_map2point ECP_BLS12383_map2point
#define G1_cfp ECP_BLS12383_cfp
#define G1_copy ECP_BLS12383_copy
#define G1_setx ECP_BLS12383_setx
// #define G1_mul ECP_BLS12383_mul
#define G1_add ECP_BLS12383_add
#define G1_toOctet ECP_BLS12383_toOctet
#define G1_get ECP_BLS12383_get
#define G1_toOctet ECP_BLS12383_toOctet
#define G1_neg ECP_BLS12383_neg
// #define G1_sub ECP_BLS12383_sub

#define G2_copy ECP2_BLS12383_copy
#define G2_isinf ECP2_BLS12383_isinf
#define G2_generator ECP2_BLS12383_generator
#define G2_map2point ECP2_BLS12383_map2point
#define G2_cfp ECP2_BLS12383_cfp
// #define G2_mul ECP2_BLS12383_mul
#define G2_get ECP2_BLS12383_get
#define G2_toOctet ECP2_BLS12383_toOctet
#define G2_add ECP2_BLS12383_add

#define GT_copy FP12_BLS12383_copy
#define GT_mul FP12_BLS12383_mul
#define GT_compow FP12_BLS12383_compow
#define GT_toOctet FP12_BLS12383_toOctet
#define GT_equals FP12_BLS12383_equals

#define FP_rand FP_BLS12383_rand
#define FP_copy FP_BLS12383_copy
#define FP_fromBytes FP_BLS12383_fromBytes
#define FP2_rand FP2_BLS12383_rand
#define FP2_copy FP2_BLS12383_copy
#define FP4_copy FP4_BLS12383_copy

#define PAIR_G1mul PAIR_BLS12383_G1mul
#define PAIR_G2mul PAIR_BLS12383_G2mul
#define PAIR_GTpow PAIR_BLS12383_GTpow

#define PAIR_ate PAIR_BLS12383_ate
#define PAIR_add PAIR_BLS12383_add
#define PAIR_fexp PAIR_BLS12383_fexp
#define PAIR_initmp PAIR_BLS12383_initmp
#define PAIR_another PAIR_BLS12383_another
#define PAIR_another_pc PAIR_BLS12383_another_pc
#define PAIR_GTmember PAIR_BLS12383_GTmember

#elif RA_PAIRING_BN254
#include "pair_BN254.h"

#elif RA_PAIR_BLS24479
#include "pair4_BLS24479.h"

#elif RA_PAIR_BLS48556
#include "pair8_BLS48556.h"

#endif
extern csprng* RNG;
extern FP4 G2_TAB[G2_TABLE];  // space for precomputation on fixed G2 parameter
extern hash SH;

void initiate();
void order(Big order);
void random_G1_generator(G1 *g);
void random_G2_generator(G2 *g);
void random_G1(G1 *h);
void random_G2(G2 *h);
void random_Big(Big b);
void pair_mult_G1(G1* result, G1* a, Big b);
void pair_mult_G2(G2* result, G2* a, Big b);
void pairing(GT* gt, G2* g2, G1* g1);
void multi_pairing(int n, GT* gt, G2* g2, G1* g1);
// void hash_and_map(G1* w,char *ID);
// void start_hash();
// void finish_hash_to_group(Big hash);
// void add_to_hash_GT_FP12(GT* v);
// void add_to_hash_G1(G1* x);
// void add_to_hash_G2(G2* x);
// void add_to_hash_Big(Big b);
// void add_to_hash_char(char* x);
// void finish_hash_to_group(Big b);
void pair_power_GT(GT* result, GT* a, Big b);
bool member(GT* gt);

void hash_Join_comm(Big c, Big order, G1* g1, G1* h1, G1* h2, 
    G2* g2, G2* w, Big ni, G1* F, G1* R);
void hash_Sign_comm(Big c, Big order, G1* g1, G1* h1, G1* h2, 
    G2* g2, G2* w, G1* B, G1* K, G1* T, G1* R1, GT* R2, Big nv);
void hash_Sign_plus(Big c, Big ch, Big nt, char* message);

void display_G1(G1* g1);
void display_G2(G2* g2);
void display_GT(GT* gt);
void display_Big(Big b);

#endif