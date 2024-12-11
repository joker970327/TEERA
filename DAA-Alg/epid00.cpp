/*
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

#include <iostream>
#include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

// #define MR_PAIRING_BN    // AES-128 or AES-192 security
// #define AES_SECURITY 128
// #define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"

typedef G1 G3;

int main()
{   
    PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
    miracl* mip=get_mip();

    time_t seed;

    // int i,j;
    G1 g1,h1,h2;
    G2 g2,w;
    GT t1,t2,t3,t4;
    G3 g3;
    Big gamma;

    time(&seed);
    irand((long)seed);

// ------------------------------------ setup ----------------------------------------	
    cout << "Setup" << endl;

    Big order=pfc.order();

    pfc.random(g1);
    pfc.random(g2);
    pfc.random(g3);
    pfc.random(h1);
    pfc.random(h2);
    pfc.random(gamma);
    w=pfc.mult(g2,gamma);

    t1=pfc.pairing(g2,g1); t2=pfc.pairing(g2,h1); t3=pfc.pairing(g2,h2); t4=pfc.pairing(w,h2);

    pfc.precomp_for_mult(g1);
    pfc.precomp_for_mult(g2);
    pfc.precomp_for_mult(g3);
    pfc.precomp_for_mult(h1);
    pfc.precomp_for_mult(h2);
    pfc.precomp_for_mult(w);
    pfc.precomp_for_pairing(g2);
    pfc.precomp_for_power(t1);
    pfc.precomp_for_power(t2);
    pfc.precomp_for_power(t3);
    pfc.precomp_for_power(t4);

// ------------------------------------ join ----------------------------------------
    cout << "Join" << endl;

// P does ...
    Big f, yp;
    G1 C;

    pfc.random(f);
    pfc.random(yp);

    C = pfc.mult(h1, f) + pfc.mult(h2, yp);

// P send C to I

    Big x, ypp;
    G1 A;

    A = pfc.mult(g1+C+pfc.mult(h2,ypp),inverse(x+gamma,order));

// I send (A, x, y'') to P

    Big y;
    y = (yp + ypp) % order;
    // P verify :
    G2 wg2x = w + pfc.mult(g2,x);
    G1 g1h1fh2y = -(g1 + pfc.mult(h1,f) + pfc.mult(h2,y));

    G1 *gf1[2]; gf1[0] = &A; gf1[1] = &g1h1fh2y;
    G2 *gf2[2]; gf2[0] = &wg2x; gf2[1] = &g2;
    
    if (pfc.multi_pairing(2,gf2,gf1)!=1)
    {
        cout << "verification fails, aborting.. " << endl;
        exit(0);
    }else{
        cout << "    in join, verification succ.. " << endl;
        // GT retz = pfc.multi_pairing(2,gf2,gf1);
        // cmp GT.g.a == 0
    }
    // P outputs sk := (A, x, y, f) where (A, x, y) is a membership certificate on f.

// ------------------------------------ sign ----------------------------------------

    cout << "Sign" << endl;

    G1 B1;
    G2 B2;
    pfc.random(B1);
    pfc.random(B2);
    
    G3 B, K;
    pfc.random(B);
    K = pfc.mult(B, f);

    Big a, b;
    pfc.random(a);
    b = (y + modmult(a, x, order)) % order;

    G1 T;
    T = A + pfc.mult(h2,a);

    Big rx ,rf, ra, rb;
    pfc.random(rx);
    pfc.random(rf);
    pfc.random(ra);
    pfc.random(rb);

    G3 R1;
    R1 = pfc.mult(B, rf);

    Big rb_arx;
    rb_arx = (rb - modmult(a, rx, order)) % order;
    GT R2;
    R2 = pfc.pairing(pfc.mult(g2, -rx), A)
        *pfc.power(t2, rf)
        *pfc.power(t3, rb_arx)
        *pfc.power(t4, ra);

    Big c;
    pfc.start_hash();
    pfc.add_to_hash(order);
    pfc.add_to_hash(g1);
    pfc.add_to_hash(g2);
    pfc.add_to_hash(g3);
    pfc.add_to_hash(h1);
    pfc.add_to_hash(h2);
    pfc.add_to_hash(w);
    pfc.add_to_hash(B);
    pfc.add_to_hash(K);
    pfc.add_to_hash(T);
    pfc.add_to_hash(R1);
    pfc.add_to_hash(R2);
    pfc.add_to_hash((char *)"Test message to be signed"); // m
    c = pfc.finish_hash_to_group();

    Big sx,sf,sa,sb;
    sx=(rx+modmult(c,x,order))%order;
    sf=(rf+modmult(c,f,order))%order;
    sa=(ra+modmult(c,a,order))%order;
    sb=(rb+modmult(c,b,order))%order;

    // Sigma_0 = (B, K, T, c, sx, sf, sa, sb).

    typedef struct
    {
        G3 Bi;
        G3 Ki;
    } sRLi;

    sRLi *sRL;

// ------------------------------------ verify ----------------------------------------

    cout << "Verify" << endl;
    
    G1 R1c;
    GT R2c;
    Big cc;
    R1c = pfc.mult(B,sf) + pfc.mult(K,-c);
    R2c = pfc.pairing(pfc.mult(g2,-sx)+pfc.mult(w,-c),T)
         *pfc.power(t1,c)
         *pfc.power(t2,sf)
         *pfc.power(t3,sb)
         *pfc.power(t4,sa);

    pfc.start_hash();
    pfc.add_to_hash(order);
    pfc.add_to_hash(g1);
    pfc.add_to_hash(g2);
    pfc.add_to_hash(g3);
    pfc.add_to_hash(h1);
    pfc.add_to_hash(h2);
    pfc.add_to_hash(w);
    pfc.add_to_hash(B);
    pfc.add_to_hash(K);
    pfc.add_to_hash(T);
    pfc.add_to_hash(R1c);
    pfc.add_to_hash(R2c);
    pfc.add_to_hash((char *)"Test message to be signed"); // m
    cc=pfc.finish_hash_to_group();

	if (cc==c){
		cout << "Verification succeeds! " << endl;
    }
	else{
		cout << "Verification fails, aborting.. " << endl;
    }
// ------------------------------------ revoke ----------------------------------------

    

    return 0;
}
