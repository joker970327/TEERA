/*
   Brickell & Li
   A Pairing-Based DAA scheme Further Reducing TPM  Resources

   Compile with modules as specified below

   For MR_PAIRING_CP curve
   cl /O2 /GX daa.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_MNT curve
   cl /O2 /GX daa.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	
   For MR_PAIRING_BN curve
   cl /O2 /GX daa.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX daa.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX daa.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

*/

// #include <iostream>
// #include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

// #include "pairing_3.h"
#include "RA_curve.h"

int main()
{   

	int i,j;
	G1 g1,h1,h2;
	G2 g2,w;
	GT t1,t2,t3,t4;
	Big gamma;

	initiate();

// setup	
	printf("Setup\n");

	Big p;
	order(p);

	random_G1_generator(&g1);
	random_G2_generator(&g2);
	random_Big(gamma);
	random_G1(&h1);
	random_G1(&h2);
	pair_mult_G2(&w,&g2,gamma);

	if (ECP_BLS12383_isinf(&g1))
    {
        printf("g1 random failed\n");
        return 0;
    }
	if (ECP2_BLS12383_isinf(&g2))
    {
        printf("g2 random failed\n");
        return 0;
    }
	if (!PAIR_BLS12383_G1member(&h1))
	{
		printf("h1 random failed\n");
		return 0;
	}
	if (!PAIR_BLS12383_G1member(&h2))
	{
		printf("h2 random failed\n");
		return 0;
	}
	if (!PAIR_BLS12383_G2member(&w))
	{
		printf("w calculate failed\n");
		return 0;
	}

	pairing(&t1,&g2,&g1);
	pairing(&t2,&g2,&h1);
	pairing(&t3,&g2,&h2);
	pairing(&t4,&w,&h2);

	if (!PAIR_GTmember(&t1))
    {
        printf("t1 pairing failed\n");
        return 0;
    }
	if (!PAIR_GTmember(&t2))
	{
		printf("t2 pairing failed\n");
		return 0;
	}
	if (!PAIR_GTmember(&t3))
	{
		printf("t3 pairing failed\n");
		return 0;
	}
	if (!PAIR_GTmember(&t4))
	{
		printf("t4 pairing failed\n");
		return 0;
	}

// join
	printf("Join\n");

	Big ni,f,sk,rf,c,sf,x,ci;
	G1 F,R;
// Issuer does..
	random_Big(ni);

// TPM does..
	random_Big(f);
	BIG_copy(sk,f);

	random_Big(rf);

	pair_mult_G1(&F,&h1,f);

	if (ECP_BLS12383_isinf(&F))
	{
		printf("F calculate failed\n");
		return 0;
	}

	pair_mult_G1(&R,&h1,rf);


	if (ECP2_BLS12383_isinf(&R))
	{
		printf("R calculate failed\n");
		return 0;
	}
	
	hash_Join_comm(c,p,&g1,&h1,&h2,&g2,&w,ni,&F,&R);

	Big tmp_Big_1;
	modmult(tmp_Big_1,c,f,p);
	modadd(sf,rf,tmp_Big_1,p);

// TPM sends comm={F,c,sf,ni} to Issuer

// Issuer does..
// Issuer should check ni is the same, and that F is not revoked
	G1 Rc,A;
	G1 tmp_G1_1;
	Big tmp_Big_2,tmp_Big_3;


	pair_mult_G1(&Rc,&h1,sf);

	BIG_modneg(tmp_Big_2, c,p);
	pair_mult_G1(&tmp_G1_1,&F,tmp_Big_2);

	if(ECP_BLS12383_isinf(&tmp_G1_1)){
		printf("tmp_G1_1 calculate failed\n");
		return 0;
	}

	G1_add(&Rc, &tmp_G1_1);

	hash_Join_comm(ci,p,&g1,&h1,&h2,&g2,&w,ni,&F,&Rc);

	if(BIG_comp(c,ci)!=0)
	{
		printf("Verification fails, aborting..\n");
		// exit(0);
		return 0;
	}

	random_Big(x);
	G1_copy(&A,&g1);
	G1_add(&A,&F);
	modadd(tmp_Big_2,x,gamma,p);
	BIG_invmodp(tmp_Big_3,tmp_Big_2,p);
	pair_mult_G1(&A,&A,tmp_Big_3);
	

// Issuer sends credential cre={A,x} to TPM
// TPM forwards F and cre to Host
// Host does..

	// wxg2 = w * g2^x
	G2 tmp_G2_1;
	G2 wxg2;
	G2_copy(&wxg2,&w);
	pair_mult_G2(&tmp_G2_1,&g2,x);
	G2_add(&wxg2,&tmp_G2_1);
	
	// g1f = g1 * F
	G1 g1f;
	G1_copy(&g1f,&g1);
	G1_add(&g1f,&F);

	GT left;
	GT right;
	pairing(&left,&wxg2,&A);
	pairing(&right,&g2,&g1f);
	if(!GT_equals(&left,&right))
	{
		printf("Verification fails, aborting.. \n");
		return 0;
	}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// sign
	printf("Sign\n");

	G1 B,K,R1,R2t,nv;
// Verifier does..
	random_G1(&nv);

// TPM does..
	hash_and_map(&B,"bsn");

	random_Big(rf);
	pair_mult_G1(&K,&B,f);
	
	pair_mult_G1(&R1,&B,rf);
	pair_mult_G1(&R2t,&h1,rf);

// TPM sends B, K, R1, R2t to Host

// Host does.. 
	G1 T;
	GT R2;
	Big a,b,rx,ra,rb,ch,nt;
	Big tmp_Big_4;
	G1 tmp_G1_3;

	random_Big(a);

	// b = a*x mod p
	modmult(b,a,x,p);

	// T = A * h2^a
	G1_copy(&T,&A);
	pair_mult_G1(&tmp_G1_3,&h2,a);
	G1_add(&T,&tmp_G1_3);

	random_Big(rx);
	random_Big(ra);
	random_Big(rb);

	// tmp_G1_3 = T^-rx * h2^rb * R2t
	BIG_modneg(tmp_Big_4, rx,p);
	pair_mult_G1(&tmp_G1_3,&T,tmp_Big_4);
	G1 tmp_G1_4;
	pair_mult_G1(&tmp_G1_4,&h2,rb);
	G1_add(&tmp_G1_3,&tmp_G1_4);
	G1_add(&tmp_G1_3,&R2t);

	// R2 = e(T^-rx * h2^rb * R2t,g2) * t4^ra
	pairing(&R2,&g2,&tmp_G1_3);
	GT tmp_GT_1;
	pair_power_GT(&tmp_GT_1,&t4,ra);
	GT_mul(&R2,&tmp_GT_1);

	hash_Sign_comm(ch,p,&g1,&h1,&h2,&g2,&w,&B,&K,&T,&R1,&R2,&nv);

	// BIG_output(ch);

// ch is sent to TPM

// TPM does..
	random_Big(nt);

	hash_Sign_plus(c,ch,nt,(char *)"Test message to be signed");
	
	// sf = (c*f mod p) + rf mod p
	Big tmp_Big_5;
	modmult(tmp_Big_5,c,f,p);
	modadd(sf,rf,tmp_Big_5,p);

// {c,nt,sf) sent to Host

	// rf=0; // rf is erased
	BIG_zero(rf);

// Host does
	Big sx,sa,sb;

	// sx = (c*x mod p) + rx mod p
	Big tmp_Big_6;
	modmult(tmp_Big_6,c,x,p);
	modadd(sx,rx,tmp_Big_6,p);

	// sa = (c*a mod p) + ra mod p
	modmult(tmp_Big_6,c,a,p);
	modadd(sa,ra,tmp_Big_6,p);

	// sb = (c*b mod p) + rb mod p
	modmult(tmp_Big_6,c,b,p);
	modadd(sb,rb,tmp_Big_6,p);

// Host outputs signature {B,K,T,c,nt,sf,sx,sa,sb}

// verify
	// cout << "Verify" << endl;
	printf("Verify\n");

	G1 R1c;
	GT R2c;
	Big cc;
	Big chv;

	// R1c = B^sf
	pair_mult_G1(&R1c,&B,sf);

	// R1c = B^sf * K^-c 
	G1 tmp_G1_5;	
	Big tmp_Big_7;
	BIG_modneg(tmp_Big_7, c,p);
	pair_mult_G1(&tmp_G1_5,&K,tmp_Big_7);
	G1_add(&R1c,&tmp_G1_5);

	// R2c = e(T, g2^-sx * w^-c) * t1^c * t2^sf * t3^sb * t4^sa
	G2 tmp_G2_2;
	BIG_modneg(tmp_Big_7, sx,p);
	pair_mult_G2(&tmp_G2_2,&g2,tmp_Big_7);
	G2 tmp_G2_3;
	BIG_modneg(tmp_Big_7, c,p);
	pair_mult_G2(&tmp_G2_3,&w,tmp_Big_7);
	G2_add(&tmp_G2_2,&tmp_G2_3);
	pairing(&R2c,&tmp_G2_2,&T);
	// tmp_GT_2 = t1^c
	GT tmp_GT_2;
	pair_power_GT(&tmp_GT_2,&t1,c);
	// tmp_GT_3 = t2^sf
	GT tmp_GT_3;
	pair_power_GT(&tmp_GT_3,&t2,sf);
	// tmp_GT_4 = t3^sb
	GT tmp_GT_4;
	pair_power_GT(&tmp_GT_4,&t3,sb);
	// tmp_GT_5 = t4^sa
	GT tmp_GT_5;
	pair_power_GT(&tmp_GT_5,&t4,sa);

	GT_mul(&R2c,&tmp_GT_2);
	GT_mul(&R2c,&tmp_GT_3);
	GT_mul(&R2c,&tmp_GT_4);
	GT_mul(&R2c,&tmp_GT_5);

	hash_Sign_comm(chv,p,&g1,&h1,&h2,&g2,&w,&B,&K,&T,&R1c,&R2c,&nv);

	// BIG_output(chv);

	hash_Sign_plus(cc,chv,nt,(char *)"Test message to be signed");

	// if (cc==c)
	if(BIG_comp(cc,c)==0)
		// cout << "Verification succeeds! " << endl;
		printf("Verification succeeds! \n");
	else
		// cout << "Verification fails, aborting.. " << endl;
		printf("Verification fails, aborting.. \n");

    return 0;
}
