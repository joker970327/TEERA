/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* CORE Elliptic Curve Functions */
/* SU=m, SU is Stack Usage (Weierstrass Curves) */

//#define HAS_MAIN

#include "ecp_BLS12383.h"

/* test for P=O point-at-infinity */
int ECP_BLS12383_isinf(ECP_BLS12383 *P)
{

#if CURVETYPE_BLS12383==EDWARDS
    return (FP_BLS12383_iszilch(&(P->x)) && FP_BLS12383_equals(&(P->y), &(P->z)));
#endif
#if CURVETYPE_BLS12383==WEIERSTRASS
    return (FP_BLS12383_iszilch(&(P->x)) && FP_BLS12383_iszilch(&(P->z)));
#endif
#if CURVETYPE_BLS12383==MONTGOMERY
    return FP_BLS12383_iszilch(&(P->z));
#endif

}

/* Conditional swap of P and Q dependant on d */
static void ECP_BLS12383_cswap(ECP_BLS12383 *P, ECP_BLS12383 *Q, int d)
{
    FP_BLS12383_cswap(&(P->x), &(Q->x), d);
#if CURVETYPE_BLS12383!=MONTGOMERY
    FP_BLS12383_cswap(&(P->y), &(Q->y), d);
#endif
    FP_BLS12383_cswap(&(P->z), &(Q->z), d);
}

#if CURVETYPE_BLS12383!=MONTGOMERY
/* Conditional move Q to P dependant on d */
static void ECP_BLS12383_cmove(ECP_BLS12383 *P, ECP_BLS12383 *Q, int d)
{
    FP_BLS12383_cmove(&(P->x), &(Q->x), d);
#if CURVETYPE_BLS12383!=MONTGOMERY
    FP_BLS12383_cmove(&(P->y), &(Q->y), d);
#endif
    FP_BLS12383_cmove(&(P->z), &(Q->z), d);
}

/* return 1 if b==c, no branching */
static int teq(sign32 b, sign32 c)
{
    sign32 x = b ^ c;
    x -= 1; // if x=0, x now -1
    return (int)((x >> 31) & 1);
}
#endif // CURVETYPE_BLS12383!=MONTGOMERY

#if CURVETYPE_BLS12383!=MONTGOMERY
/* Constant time select from pre-computed table */
static void ECP_BLS12383_select(ECP_BLS12383 *P, ECP_BLS12383 W[], sign32 b)
{
    ECP_BLS12383 MP;
    sign32 m = b >> 31;
    sign32 babs = (b ^ m) - m;

    babs = (babs - 1) / 2;

    ECP_BLS12383_cmove(P, &W[0], teq(babs, 0)); // conditional move
    ECP_BLS12383_cmove(P, &W[1], teq(babs, 1));
    ECP_BLS12383_cmove(P, &W[2], teq(babs, 2));
    ECP_BLS12383_cmove(P, &W[3], teq(babs, 3));
    ECP_BLS12383_cmove(P, &W[4], teq(babs, 4));
    ECP_BLS12383_cmove(P, &W[5], teq(babs, 5));
    ECP_BLS12383_cmove(P, &W[6], teq(babs, 6));
    ECP_BLS12383_cmove(P, &W[7], teq(babs, 7));

    ECP_BLS12383_copy(&MP, P);
    ECP_BLS12383_neg(&MP);  // minus P
    ECP_BLS12383_cmove(P, &MP, (int)(m & 1));
}
#endif

/* Test P == Q */
/* SU=168 */
int ECP_BLS12383_equals(ECP_BLS12383 *P, ECP_BLS12383 *Q)
{
    FP_BLS12383 a, b;

    FP_BLS12383_mul(&a, &(P->x), &(Q->z));
    FP_BLS12383_mul(&b, &(Q->x), &(P->z));
    if (!FP_BLS12383_equals(&a, &b)) return 0;

#if CURVETYPE_BLS12383!=MONTGOMERY
    FP_BLS12383_mul(&a, &(P->y), &(Q->z));
    FP_BLS12383_mul(&b, &(Q->y), &(P->z));
    if (!FP_BLS12383_equals(&a, &b)) return 0;
#endif

    return 1;

}

/* Set P=Q */
/* SU=16 */
void ECP_BLS12383_copy(ECP_BLS12383 *P, ECP_BLS12383 *Q)
{
    FP_BLS12383_copy(&(P->x), &(Q->x));
#if CURVETYPE_BLS12383!=MONTGOMERY
    FP_BLS12383_copy(&(P->y), &(Q->y));
#endif
    FP_BLS12383_copy(&(P->z), &(Q->z));
}

/* Set P=-Q */
#if CURVETYPE_BLS12383!=MONTGOMERY
/* SU=8 */
void ECP_BLS12383_neg(ECP_BLS12383 *P)
{
#if CURVETYPE_BLS12383==WEIERSTRASS
    FP_BLS12383_neg(&(P->y), &(P->y));
    FP_BLS12383_norm(&(P->y));
#else
    FP_BLS12383_neg(&(P->x), &(P->x));
    FP_BLS12383_norm(&(P->x));
#endif

}
#endif

/* Set P=O */
void ECP_BLS12383_inf(ECP_BLS12383 *P)
{
    FP_BLS12383_zero(&(P->x));
#if CURVETYPE_BLS12383!=MONTGOMERY
    FP_BLS12383_one(&(P->y));
#endif
#if CURVETYPE_BLS12383!=EDWARDS
    FP_BLS12383_zero(&(P->z));
#else
    FP_BLS12383_one(&(P->z));
#endif
}

/* Calculate right Hand Side of curve equation y^2=RHS */
/* SU=56 */
void ECP_BLS12383_rhs(FP_BLS12383 *v, FP_BLS12383 *x)
{
#if CURVETYPE_BLS12383==WEIERSTRASS
    /* x^3+Ax+B */
    FP_BLS12383 t;
    FP_BLS12383_sqr(&t, x);
    FP_BLS12383_mul(&t, &t, x);

#if CURVE_A_BLS12383 == -3

        FP_BLS12383_neg(v, x);
        FP_BLS12383_norm(v);
        FP_BLS12383_imul(v, v, -CURVE_A_BLS12383);
        FP_BLS12383_norm(v);
        FP_BLS12383_add(v, &t, v);
#else 
        FP_BLS12383_copy(v, &t);
#endif

    FP_BLS12383_rcopy(&t, CURVE_B_BLS12383);

    FP_BLS12383_add(v, &t, v);
    FP_BLS12383_reduce(v);
#endif

#if CURVETYPE_BLS12383==EDWARDS
    /* (Ax^2-1)/(Bx^2-1) */
    FP_BLS12383 t, one;
    FP_BLS12383_sqr(v, x);
    FP_BLS12383_one(&one);
    FP_BLS12383_rcopy(&t, CURVE_B_BLS12383);

    FP_BLS12383_mul(&t, v, &t);
    FP_BLS12383_sub(&t, &t, &one);
    FP_BLS12383_norm(&t);
#if CURVE_A_BLS12383 == 1
        FP_BLS12383_sub(v, v, &one);
#endif

#if CURVE_A_BLS12383 == -1
        FP_BLS12383_add(v, v, &one);
        FP_BLS12383_norm(v);
        FP_BLS12383_neg(v, v);
#endif
    FP_BLS12383_norm(v);
    FP_BLS12383_inv(&t, &t, NULL);
    FP_BLS12383_mul(v, v, &t);
    FP_BLS12383_reduce(v);
#endif

#if CURVETYPE_BLS12383==MONTGOMERY
    /* x^3+Ax^2+x */
    FP_BLS12383 x2, x3;
    FP_BLS12383_sqr(&x2, x);
    FP_BLS12383_mul(&x3, &x2, x);
    FP_BLS12383_copy(v, x);
    FP_BLS12383_imul(&x2, &x2, CURVE_A_BLS12383);
    FP_BLS12383_add(v, v, &x2);
    FP_BLS12383_add(v, v, &x3);
    FP_BLS12383_reduce(v);
#endif
}

#if CURVETYPE_BLS12383==MONTGOMERY

/* Set P=(x,{y}) */

int ECP_BLS12383_set(ECP_BLS12383 *P, BIG_384_58 x)
{
    //BIG_384_58 m, b;
    FP_BLS12383 rhs;
    //BIG_384_58_rcopy(m, Modulus_BLS12383);

    FP_BLS12383_nres(&rhs, x);

    ECP_BLS12383_rhs(&rhs, &rhs);

    //FP_BLS12383_redc(b, &rhs);
    //if (BIG_384_58_jacobi(b, m) != 1)
    if (!FP_BLS12383_qr(&rhs,NULL))
    {
        ECP_BLS12383_inf(P);
        return 0;
    }

    FP_BLS12383_nres(&(P->x), x);
    FP_BLS12383_one(&(P->z));
    return 1;
}

/* Extract x coordinate as BIG */
int ECP_BLS12383_get(BIG_384_58 x, ECP_BLS12383 *P)
{
    ECP_BLS12383 W;
    ECP_BLS12383_copy(&W, P);
    ECP_BLS12383_affine(&W);
    if (ECP_BLS12383_isinf(&W)) return -1;
    FP_BLS12383_redc(x, &(W.x));
    return 0;
}


#else
/* Extract (x,y) and return sign of y. If x and y are the same return only x */
/* SU=16 */
int ECP_BLS12383_get(BIG_384_58 x, BIG_384_58 y, ECP_BLS12383 *P)
{
    ECP_BLS12383 W;
    ECP_BLS12383_copy(&W, P);
    ECP_BLS12383_affine(&W);

    if (ECP_BLS12383_isinf(&W)) return -1;

    FP_BLS12383_redc(y, &(W.y));
    FP_BLS12383_redc(x, &(W.x));

    return FP_BLS12383_sign(&(W.x));
}

/* Set P=(x,{y}) */
/* SU=96 */
int ECP_BLS12383_set(ECP_BLS12383 *P, BIG_384_58 x, BIG_384_58 y)
{
    FP_BLS12383 rhs, y2;

    FP_BLS12383_nres(&y2, y);
    FP_BLS12383_sqr(&y2, &y2);
    FP_BLS12383_reduce(&y2);

    FP_BLS12383_nres(&rhs, x);
    ECP_BLS12383_rhs(&rhs, &rhs);

    if (!FP_BLS12383_equals(&y2, &rhs))
    {
        ECP_BLS12383_inf(P);
        return 0;
    }

    FP_BLS12383_nres(&(P->x), x);
    FP_BLS12383_nres(&(P->y), y);
    FP_BLS12383_one(&(P->z));
    return 1;
}

/* Set P=(x,y), where y is calculated from x with sign s */
/* SU=136 */
int ECP_BLS12383_setx(ECP_BLS12383 *P, BIG_384_58 x, int s)
{
    FP_BLS12383 rhs,hint;
    FP_BLS12383_nres(&rhs, x);

    ECP_BLS12383_rhs(&rhs, &rhs);

    if (!FP_BLS12383_qr(&rhs,&hint))
    {
        ECP_BLS12383_inf(P);
        return 0;
    }

    FP_BLS12383_nres(&(P->x), x);
    FP_BLS12383_sqrt(&(P->y), &rhs,&hint);

    if (FP_BLS12383_sign(&(P->y))!=s)
        FP_BLS12383_neg(&(P->y), &(P->y));
    FP_BLS12383_reduce(&(P->y));
    FP_BLS12383_one(&(P->z));
    return 1;
}

#endif

void ECP_BLS12383_cfp(ECP_BLS12383 *P)
{   /* multiply point by curves cofactor */
    BIG_384_58 c;
    int cf = CURVE_Cof_I_BLS12383;
    if (cf == 1) return;
    if (cf == 4)
    {
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_dbl(P);
        return;
    }
    if (cf == 8)
    {
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_dbl(P);
        return;
    }
    BIG_384_58_rcopy(c, CURVE_Cof_BLS12383);
    ECP_BLS12383_mul(P, c);
    return;
}

/* Hunt and Peck a BIG to a curve point */
/*
void ECP_BLS12383_hap2point(ECP_BLS12383 *P,BIG_384_58 h)
{
    BIG_384_58 x;
    BIG_384_58_copy(x,h);

	for (;;)
	{
#if CURVETYPE_BLS12383!=MONTGOMERY
		ECP_BLS12383_setx(P,x,0);
#else
		ECP_BLS12383_set(P,x);
#endif
		BIG_384_58_inc(x,1); BIG_384_58_norm(x);
		if (!ECP_BLS12383_isinf(P)) break;
	}
}
*/
/* Constant time Map to Point */
void ECP_BLS12383_map2point(ECP_BLS12383 *P,FP_BLS12383 *h)
{
#if CURVETYPE_BLS12383==MONTGOMERY
// Elligator 2
    int qres;
    BIG_384_58 a;
    FP_BLS12383 X1,X2,w,t,one,A,N,D,hint;
    //BIG_384_58_zero(a); BIG_384_58_inc(a,CURVE_A_BLS12383); BIG_384_58_norm(a); FP_BLS12383_nres(&A,a);
    FP_BLS12383_from_int(&A,CURVE_A_BLS12383);
    FP_BLS12383_copy(&t,h);
    FP_BLS12383_sqr(&t,&t);   // t^2

    if (PM1D2_BLS12383 == 2)
        FP_BLS12383_add(&t,&t,&t);  // 2t^2
    if (PM1D2_BLS12383 == 1)
        FP_BLS12383_neg(&t,&t);      // -t^2
    if (PM1D2_BLS12383 > 2)
        FP_BLS12383_imul(&t,&t,QNRI_BLS12383); // precomputed QNR
    FP_BLS12383_norm(&t);  // z.t^2

    FP_BLS12383_one(&one);
    FP_BLS12383_add(&D,&t,&one); FP_BLS12383_norm(&D);  // Denominator D=1+z.t^2

    FP_BLS12383_copy(&X1,&A);
    FP_BLS12383_neg(&X1,&X1);  FP_BLS12383_norm(&X1);  // X1 = -A/D
    FP_BLS12383_copy(&X2,&X1);
    FP_BLS12383_mul(&X2,&X2,&t);             // X2 = -At/D

    FP_BLS12383_sqr(&w,&X1); FP_BLS12383_mul(&N,&w,&X1);  // w=X1^2, N=X1^3
    FP_BLS12383_mul(&w,&w,&A); FP_BLS12383_mul(&w,&w,&D); FP_BLS12383_add(&N,&N,&w);  // N = X1^3+ADX1^2
    FP_BLS12383_sqr(&t,&D);
    FP_BLS12383_mul(&t,&t,&X1);  
    FP_BLS12383_add(&N,&N,&t);  // N=X1^3+ADX1^2+D^2X1  // Numerator of gx =  N/D^3
    FP_BLS12383_norm(&N);

    FP_BLS12383_mul(&t,&N,&D);                   // N.D
    qres=FP_BLS12383_qr(&t,&hint);  // *** exp
    FP_BLS12383_inv(&w,&t,&hint);
    FP_BLS12383_mul(&D,&w,&N);     // 1/D
    FP_BLS12383_mul(&X1,&X1,&D);    // get X1
    FP_BLS12383_mul(&X2,&X2,&D);    // get X2
    FP_BLS12383_cmove(&X1,&X2,1-qres);
    FP_BLS12383_redc(a,&X1);

    ECP_BLS12383_set(P,a);
    return;
#endif

#if CURVETYPE_BLS12383==EDWARDS
// Elligator 2 - map to Montgomery, place point, map back
    int qres,ne,rfc,qnr;
    BIG_384_58 x,y;
    FP_BLS12383 X1,X2,t,w,one,A,w1,w2,B,Y,K,D,hint;
    FP_BLS12383_one(&one);

#if MODTYPE_BLS12383 != GENERALISED_MERSENNE
// its NOT ed448!
// Figure out the Montgomery curve parameters

    FP_BLS12383_rcopy(&B,CURVE_B_BLS12383);
#if CURVE_A_BLS12383 ==  1
        FP_BLS12383_add(&A,&B,&one);  // A=B+1
        FP_BLS12383_sub(&B,&B,&one);   // B=B-1
#else
        FP_BLS12383_sub(&A,&B,&one);  // A=B-1
        FP_BLS12383_add(&B,&B,&one);  // B=B+1
#endif
    FP_BLS12383_norm(&A); FP_BLS12383_norm(&B);

    FP_BLS12383_div2(&A,&A);    // (A+B)/2
    FP_BLS12383_div2(&B,&B);    // (B-A)/2
    FP_BLS12383_div2(&B,&B);    // (B-A)/4

    FP_BLS12383_neg(&K,&B); FP_BLS12383_norm(&K);
    //FP_BLS12383_inv(&K,&K,NULL);    // K
    FP_BLS12383_invsqrt(&K,&w1,&K);

    rfc=RIADZ_BLS12383;
    if (rfc)
    { // RFC7748 method applies
        FP_BLS12383_mul(&A,&A,&K);   // = J
        FP_BLS12383_mul(&K,&K,&w1);
        //FP_BLS12383_sqrt(&K,&K,NULL);
    } else { // generic method
        FP_BLS12383_sqr(&B,&B);
    }
#else
    FP_BLS12383_from_int(&A,156326);
    rfc=1;
#endif
// Map to this Montgomery curve X^2=X^3+AX^2+BX

    FP_BLS12383_copy(&t,h); 
    FP_BLS12383_sqr(&t,&t);   // t^2

    if (PM1D2_BLS12383 == 2)
    {
        FP_BLS12383_add(&t,&t,&t);  // 2t^2
        qnr=2;
    }
    if (PM1D2_BLS12383 == 1)
    {
        FP_BLS12383_neg(&t,&t);      // -t^2
        qnr=-1;
    }
    if (PM1D2_BLS12383 > 2)
    {
        FP_BLS12383_imul(&t,&t,QNRI_BLS12383);  // precomputed QNR
        qnr=QNRI_BLS12383;
    }
    FP_BLS12383_norm(&t);
    FP_BLS12383_add(&D,&t,&one); FP_BLS12383_norm(&D);  // Denominator=(1+z.u^2)

    FP_BLS12383_copy(&X1,&A);
    FP_BLS12383_neg(&X1,&X1);  FP_BLS12383_norm(&X1);    // X1=-(J/K).inv(1+z.u^2)
    FP_BLS12383_mul(&X2,&X1,&t);  // X2=X1*z.u^2

// Figure out RHS of Montgomery curve in rational form gx1/d^3

    FP_BLS12383_sqr(&w,&X1); FP_BLS12383_mul(&w1,&w,&X1);  // w=X1^2, w1=X1^3
    FP_BLS12383_mul(&w,&w,&A); FP_BLS12383_mul(&w,&w,&D); FP_BLS12383_add(&w1,&w1,&w);  // w1 = X1^3+ADX1^2
    FP_BLS12383_sqr(&w2,&D);
    if (!rfc)
    {
        FP_BLS12383_mul(&w,&X1,&B);
        FP_BLS12383_mul(&w2,&w2,&w); //
        FP_BLS12383_add(&w1,&w1,&w2);   // w1=X1^3+ADX1^2+BD^2X1
    } else {
        FP_BLS12383_mul(&w2,&w2,&X1);  
        FP_BLS12383_add(&w1,&w1,&w2);  // w1=X1^3+ADX1^2+D^2X1  // was &X1
    }
    FP_BLS12383_norm(&w1);

    FP_BLS12383_mul(&B,&w1,&D);     // gx1=num/den^3 - is_qr num*den (same as num/den, same as num/den^3)
    qres=FP_BLS12383_qr(&B,&hint);  // ***
    FP_BLS12383_inv(&w,&B,&hint);
    FP_BLS12383_mul(&D,&w,&w1);     // 1/D
    FP_BLS12383_mul(&X1,&X1,&D);    // get X1
    FP_BLS12383_mul(&X2,&X2,&D);    // get X2
    FP_BLS12383_sqr(&D,&D);

    FP_BLS12383_imul(&w1,&B,qnr);       // now for gx2 = Z.u^2.gx1
    FP_BLS12383_rcopy(&w,CURVE_HTPC_BLS12383);   // qnr^C3  
    FP_BLS12383_mul(&w,&w,&hint);    // modify hint for gx2
    FP_BLS12383_mul(&w2,&D,h);

    FP_BLS12383_cmove(&X1,&X2,1-qres);  // pick correct one
    FP_BLS12383_cmove(&B,&w1,1-qres);
    FP_BLS12383_cmove(&hint,&w,1-qres);
    FP_BLS12383_cmove(&D,&w2,1-qres);
     
    FP_BLS12383_sqrt(&Y,&B,&hint);   // sqrt(num*den)
    FP_BLS12383_mul(&Y,&Y,&D);       // sqrt(num/den^3)

/*
    FP_BLS12383_sqrt(&Y,&B,&hint);   // sqrt(num*den)
    FP_BLS12383_mul(&Y,&Y,&D);       // sqrt(num/den^3)

    FP_BLS12383_imul(&B,&B,qnr);     // now for gx2 = Z.u^2.gx1
    FP_BLS12383_rcopy(&w,CURVE_HTPC_BLS12383);   // qnr^C3  
    FP_BLS12383_mul(&hint,&hint,&w);    // modify hint for gx2

    FP_BLS12383_sqrt(&Y3,&B,&hint);  // second candidate
    FP_BLS12383_mul(&D,&D,h);
    FP_BLS12383_mul(&Y3,&Y3,&D);

    FP_BLS12383_cmove(&X1,&X2,1-qres);  // pick correct one
    FP_BLS12383_cmove(&Y,&Y3,1-qres);
*/
// correct sign of Y
    FP_BLS12383_neg(&w,&Y); FP_BLS12383_norm(&w);
    FP_BLS12383_cmove(&Y,&w,qres^FP_BLS12383_sign(&Y));

    if (!rfc)
    {
        FP_BLS12383_mul(&X1,&X1,&K);
        FP_BLS12383_mul(&Y,&Y,&K);
    }

#if MODTYPE_BLS12383 == GENERALISED_MERSENNE
// Ed448 isogeny
    FP_BLS12383_sqr(&t,&X1);  // t=u^2
    FP_BLS12383_add(&w,&t,&one); // w=u^2+1
    FP_BLS12383_norm(&w);
    FP_BLS12383_sub(&t,&t,&one); // t=u^2-1
    FP_BLS12383_norm(&t);
    FP_BLS12383_mul(&w1,&t,&Y);  // w1=v(u^2-1)
    FP_BLS12383_add(&w1,&w1,&w1);
    FP_BLS12383_add(&X2,&w1,&w1);
    FP_BLS12383_norm(&X2);       // w1=4v(u^2-1)
    FP_BLS12383_sqr(&t,&t);      // t=(u^2-1)^2
    FP_BLS12383_sqr(&Y,&Y);      // v^2
    FP_BLS12383_add(&Y,&Y,&Y);
    FP_BLS12383_add(&Y,&Y,&Y);
    FP_BLS12383_norm(&Y);        // 4v^2
    FP_BLS12383_add(&B,&t,&Y);  // w2=(u^2-1)^2+4v^2
    FP_BLS12383_norm(&B);                                   // X1=w1/w2 - X2=w1, B=w2

    FP_BLS12383_sub(&w2,&Y,&t);   // w2=4v^2-(u^2-1)^2
    FP_BLS12383_norm(&w2);
    FP_BLS12383_mul(&w2,&w2,&X1); // w2=u(4v^2-(u^2-1)^2)
    FP_BLS12383_mul(&t,&t,&X1);   // t=u(u^2-1)^2
    FP_BLS12383_div2(&Y,&Y);      // 2v^2
    FP_BLS12383_mul(&w1,&Y,&w);  // w1=2v^2(u^2+1)
    FP_BLS12383_sub(&w1,&t,&w1);  // w1=u(u^2-1)^2 - 2v^2(u^2+1)
    FP_BLS12383_norm(&w1);                                   // Y=w2/w1

    FP_BLS12383_mul(&t,&X2,&w1);    // output in projective to avoid inversion
    FP_BLS12383_copy(&(P->x),&t);
    FP_BLS12383_mul(&t,&w2,&B);
    FP_BLS12383_copy(&(P->y),&t);
    FP_BLS12383_mul(&t,&w1,&B);
    FP_BLS12383_copy(&(P->z),&t);

    return;

#else
    FP_BLS12383_add(&w1,&X1,&one); FP_BLS12383_norm(&w1); // (s+1)
    FP_BLS12383_sub(&w2,&X1,&one); FP_BLS12383_norm(&w2); // (s-1)
    FP_BLS12383_mul(&t,&w1,&Y);
    FP_BLS12383_mul(&X1,&X1,&w1);

    if (rfc)
        FP_BLS12383_mul(&X1,&X1,&K);

    FP_BLS12383_mul(&Y,&Y,&w2);      // output in projective to avoid inversion
    FP_BLS12383_copy(&(P->x),&X1);
    FP_BLS12383_copy(&(P->y),&Y);
    FP_BLS12383_copy(&(P->z),&t);
    return;
#endif

#endif

#if CURVETYPE_BLS12383==WEIERSTRASS
    int sgn,ne;
    BIG_384_58 a,x,y;
    FP_BLS12383 X1,X2,X3,t,w,one,A,B,Y,D;
    FP_BLS12383 D2,hint,GX1;

#if HTC_ISO_BLS12383 != 0
// Map to point on isogenous curve
    int i,k,isox,isoy,iso=HTC_ISO_BLS12383;
    FP_BLS12383 xnum,xden,ynum,yden;
    BIG_384_58 z;
    FP_BLS12383_rcopy(&A,CURVE_Ad_BLS12383);
    FP_BLS12383_rcopy(&B,CURVE_Bd_BLS12383);
#else
    FP_BLS12383_from_int(&A,CURVE_A_BLS12383);
    FP_BLS12383_rcopy(&B,CURVE_B_BLS12383);
#endif

    FP_BLS12383_one(&one);
    FP_BLS12383_copy(&t,h);
    sgn=FP_BLS12383_sign(&t);

#if CURVE_A_BLS12383 != 0 || HTC_ISO_BLS12383 != 0

        FP_BLS12383_sqr(&t,&t);
        FP_BLS12383_imul(&t,&t,RIADZ_BLS12383);  // Z from hash-to-point draft standard
        FP_BLS12383_add(&w,&t,&one);     // w=Zt^2+1
        FP_BLS12383_norm(&w);

        FP_BLS12383_mul(&w,&w,&t);      // w=Z^2*t^4+Zt^2
        FP_BLS12383_mul(&D,&A,&w);      // A=Aw
                               
        FP_BLS12383_add(&w,&w,&one); FP_BLS12383_norm(&w);
        FP_BLS12383_mul(&w,&w,&B);
        FP_BLS12383_neg(&w,&w);          // -B(w+1)
        FP_BLS12383_norm(&w);

        FP_BLS12383_copy(&X2,&w);        // Numerators
        FP_BLS12383_mul(&X3,&t,&X2);

// x^3+Ad^2x+Bd^3
        FP_BLS12383_sqr(&GX1,&X2);
        FP_BLS12383_sqr(&D2,&D); FP_BLS12383_mul(&w,&A,&D2); FP_BLS12383_add(&GX1,&GX1,&w); FP_BLS12383_norm(&GX1); FP_BLS12383_mul(&GX1,&GX1,&X2); FP_BLS12383_mul(&D2,&D2,&D); FP_BLS12383_mul(&w,&B,&D2); FP_BLS12383_add(&GX1,&GX1,&w); FP_BLS12383_norm(&GX1);

        FP_BLS12383_mul(&w,&GX1,&D);
        int qr=FP_BLS12383_qr(&w,&hint);   // qr(ad) - only exp happens here
        FP_BLS12383_inv(&D,&w,&hint);     // d=1/(ad)
        FP_BLS12383_mul(&D,&D,&GX1);     // 1/d
        FP_BLS12383_mul(&X2,&X2,&D);     // X2/=D
        FP_BLS12383_mul(&X3,&X3,&D);     // X3/=D
        FP_BLS12383_mul(&t,&t,h);        // t=Z.u^3
        FP_BLS12383_sqr(&D2,&D);

        FP_BLS12383_mul(&D,&D2,&t);
        FP_BLS12383_imul(&t,&w,RIADZ_BLS12383);
        FP_BLS12383_rcopy(&X1,CURVE_HTPC_BLS12383);     
        FP_BLS12383_mul(&X1,&X1,&hint); // modify hint

        FP_BLS12383_cmove(&X2,&X3,1-qr); 
        FP_BLS12383_cmove(&D2,&D,1-qr);
        FP_BLS12383_cmove(&w,&t,1-qr);
        FP_BLS12383_cmove(&hint,&X1,1-qr);

        FP_BLS12383_sqrt(&Y,&w,&hint);  // first candidate if X2 is correct
        FP_BLS12383_mul(&Y,&Y,&D2);

/*
        FP_BLS12383_sqrt(&Y,&w,&hint);  // first candidate if X2 is correct
        FP_BLS12383_mul(&Y,&Y,&D2);

        FP_BLS12383_mul(&D2,&D2,&t);     // second candidate if X3 is correct
        FP_BLS12383_imul(&w,&w,RIADZ_BLS12383); 

        FP_BLS12383_rcopy(&X1,CURVE_HTPC_BLS12383);     
        FP_BLS12383_mul(&hint,&hint,&X1); // modify hint

        FP_BLS12383_sqrt(&Y3,&w,&hint);
        FP_BLS12383_mul(&Y3,&Y3,&D2);

        FP_BLS12383_cmove(&X2,&X3,!qr); 
        FP_BLS12383_cmove(&Y,&Y3,!qr); 
*/
        ne=FP_BLS12383_sign(&Y)^sgn;
        FP_BLS12383_neg(&w,&Y); FP_BLS12383_norm(&w);
        FP_BLS12383_cmove(&Y,&w,ne);

#if HTC_ISO_BLS12383 != 0

// (X2,Y) is on isogenous curve
        k=0;
        isox=iso;
        isoy=3*(iso-1)/2;

// xnum
        FP_BLS12383_rcopy(&xnum,PC_BLS12383[k++]);
        for (i=0;i<isox;i++)
        {
            FP_BLS12383_mul(&xnum,&xnum,&X2); 
            FP_BLS12383_rcopy(&w,PC_BLS12383[k++]);
            FP_BLS12383_add(&xnum,&xnum,&w); FP_BLS12383_norm(&xnum);
        }

// xden
        FP_BLS12383_copy(&xden,&X2);
        FP_BLS12383_rcopy(&w,PC_BLS12383[k++]);
        FP_BLS12383_add(&xden,&xden,&w); FP_BLS12383_norm(&xden);
 
        for (i=0;i<isox-2;i++)
        {
            FP_BLS12383_mul(&xden,&xden,&X2);
            FP_BLS12383_rcopy(&w,PC_BLS12383[k++]);
            FP_BLS12383_add(&xden,&xden,&w); FP_BLS12383_norm(&xden);
        }

// ynum
        FP_BLS12383_rcopy(&ynum,PC_BLS12383[k++]);
        for (i=0;i<isoy;i++)
        {
            FP_BLS12383_mul(&ynum,&ynum,&X2); 
            FP_BLS12383_rcopy(&w,PC_BLS12383[k++]);
            FP_BLS12383_add(&ynum,&ynum,&w); FP_BLS12383_norm(&ynum);
        }

// yden 
        FP_BLS12383_copy(&yden,&X2);
        FP_BLS12383_rcopy(&w,PC_BLS12383[k++]);
        FP_BLS12383_add(&yden,&yden,&w); FP_BLS12383_norm(&yden);
      
        for (i=0;i<isoy-1;i++)
        {
            FP_BLS12383_mul(&yden,&yden,&X2); 
            FP_BLS12383_rcopy(&w,PC_BLS12383[k++]);
            FP_BLS12383_add(&yden,&yden,&w); FP_BLS12383_norm(&yden);
        }

        FP_BLS12383_mul(&ynum,&ynum,&Y);

// return in projective coordinates
        FP_BLS12383_mul(&t,&xnum,&yden);
        FP_BLS12383_copy(&(P->x),&t);

        FP_BLS12383_mul(&t,&ynum,&xden);
        FP_BLS12383_copy(&(P->y),&t);

        FP_BLS12383_mul(&t,&xden,&yden);
        FP_BLS12383_copy(&(P->z),&t);
        return;
#else

        FP_BLS12383_redc(x,&X2);
        FP_BLS12383_redc(y,&Y);
        ECP_BLS12383_set(P,x,y);
        return;
#endif
#else 
// SVDW - Shallue and van de Woestijne
        FP_BLS12383_from_int(&Y,RIADZ_BLS12383);
        ECP_BLS12383_rhs(&A,&Y);  // A=g(Z)
        FP_BLS12383_rcopy(&B,SQRTm3_BLS12383);
        FP_BLS12383_imul(&B,&B,RIADZ_BLS12383); // Z*sqrt(-3)

        FP_BLS12383_sqr(&t,&t);
        FP_BLS12383_mul(&Y,&A,&t);   // tv1=u^2*g(Z)
        FP_BLS12383_add(&t,&one,&Y); FP_BLS12383_norm(&t); // tv2=1+tv1
        FP_BLS12383_sub(&Y,&one,&Y); FP_BLS12383_norm(&Y); // tv1=1-tv1
        FP_BLS12383_mul(&D,&t,&Y);
        FP_BLS12383_mul(&D,&D,&B);

        FP_BLS12383_copy(&w,&A);
        FP_BLS12383_tpo(&D,&w);   // tv3=inv0(tv1*tv2*z*sqrt(-3)) and sqrt(g(Z))   // ***

        FP_BLS12383_mul(&w,&w,&B);  // tv4=Z.sqrt(-3).sqrt(g(Z))
        if (FP_BLS12383_sign(&w)==1)
        { // depends only on sign of constant RIADZ
            FP_BLS12383_neg(&w,&w);
            FP_BLS12383_norm(&w);
        }
        FP_BLS12383_mul(&w,&w,&B);  // Z.sqrt(-3)
        FP_BLS12383_mul(&w,&w,h);    // u
        FP_BLS12383_mul(&w,&w,&Y);   // tv1
        FP_BLS12383_mul(&w,&w,&D);  // tv3   // tv5=u*tv1*tv3*tv4*Z*sqrt(-3)

        FP_BLS12383_from_int(&X1,RIADZ_BLS12383);
        FP_BLS12383_copy(&X3,&X1);
        FP_BLS12383_neg(&X1,&X1); FP_BLS12383_norm(&X1); FP_BLS12383_div2(&X1,&X1); // -Z/2
        FP_BLS12383_copy(&X2,&X1);
        FP_BLS12383_sub(&X1,&X1,&w); FP_BLS12383_norm(&X1);
        FP_BLS12383_add(&X2,&X2,&w); FP_BLS12383_norm(&X2);
        FP_BLS12383_add(&A,&A,&A);
        FP_BLS12383_add(&A,&A,&A);
        FP_BLS12383_norm(&A);      // 4*g(Z)
        FP_BLS12383_sqr(&t,&t);
        FP_BLS12383_mul(&t,&t,&D);
        FP_BLS12383_sqr(&t,&t);    // (tv2^2*tv3)^2
        FP_BLS12383_mul(&A,&A,&t); // 4*g(Z)*(tv2^2*tv3)^2

        FP_BLS12383_add(&X3,&X3,&A); FP_BLS12383_norm(&X3);

        ECP_BLS12383_rhs(&w,&X2);
        FP_BLS12383_cmove(&X3,&X2,FP_BLS12383_qr(&w,NULL));                           // ***
        ECP_BLS12383_rhs(&w,&X1);
        FP_BLS12383_cmove(&X3,&X1,FP_BLS12383_qr(&w,NULL));                           // ***
        ECP_BLS12383_rhs(&w,&X3);
        FP_BLS12383_sqrt(&Y,&w,NULL);                                        // ***
        FP_BLS12383_redc(x,&X3);

        ne=FP_BLS12383_sign(&Y)^sgn;
        FP_BLS12383_neg(&w,&Y); FP_BLS12383_norm(&w);
        FP_BLS12383_cmove(&Y,&w,ne);

        FP_BLS12383_redc(y,&Y);
        ECP_BLS12383_set(P,x,y);
        return;
#endif

#endif
}


/* Map octet to point */
/*
void ECP_BLS12383_mapit(ECP_BLS12383 *P, octet *W)
{
    BIG_384_58 q, x;
    DBIG_384_58 dx;
    BIG_384_58_rcopy(q, Modulus_BLS12383);
    BIG_384_58_dfromBytesLen(dx, W->val,W->len);
    BIG_384_58_dmod(x, dx, q);
    ECP_BLS12383_hap2point(P,x);
    ECP_BLS12383_cfp(P);
}
*/
/* Convert P to Affine, from (x,y,z) to (x,y) */
/* SU=160 */
void ECP_BLS12383_affine(ECP_BLS12383 *P)
{
    FP_BLS12383 one, iz;
    if (ECP_BLS12383_isinf(P)) return;
    FP_BLS12383_one(&one);
    if (FP_BLS12383_equals(&(P->z), &one)) return;

    FP_BLS12383_inv(&iz, &(P->z),NULL);
    FP_BLS12383_mul(&(P->x), &(P->x), &iz);

#if CURVETYPE_BLS12383==EDWARDS || CURVETYPE_BLS12383==WEIERSTRASS

    FP_BLS12383_mul(&(P->y), &(P->y), &iz);
    FP_BLS12383_reduce(&(P->y));

#endif

    FP_BLS12383_reduce(&(P->x));
    FP_BLS12383_copy(&(P->z), &one);
}

/* SU=120 */
void ECP_BLS12383_outputxyz(ECP_BLS12383 *P)
{
    BIG_384_58 x, z;
    if (ECP_BLS12383_isinf(P))
    {
        printf("Infinity\n");
        return;
    }
    FP_BLS12383_reduce(&(P->x));
    FP_BLS12383_redc(x, &(P->x));
    FP_BLS12383_reduce(&(P->z));
    FP_BLS12383_redc(z, &(P->z));

#if CURVETYPE_BLS12383!=MONTGOMERY
    BIG_384_58 y;
    FP_BLS12383_reduce(&(P->y));
    FP_BLS12383_redc(y, &(P->y));
    printf("(");
    BIG_384_58_output(x);
    printf(",");
    BIG_384_58_output(y);
    printf(",");
    BIG_384_58_output(z);
    printf(")\n");

#else
    printf("(");
    BIG_384_58_output(x);
    printf(",");
    BIG_384_58_output(z);
    printf(")\n");
#endif
}

/* SU=16 */
/* Output point P */
void ECP_BLS12383_output(ECP_BLS12383 *P)
{
    BIG_384_58 x;
    if (ECP_BLS12383_isinf(P))
    {
        printf("Infinity\n");
        return;
    }
    ECP_BLS12383_affine(P);
#if CURVETYPE_BLS12383!=MONTGOMERY
    BIG_384_58 y;
    FP_BLS12383_redc(x, &(P->x));
    FP_BLS12383_redc(y, &(P->y));
    printf("(");
    BIG_384_58_output(x);
    printf(",");
    BIG_384_58_output(y);
    printf(")\n");
#else
    FP_BLS12383_redc(x, &(P->x));
    printf("(");
    BIG_384_58_output(x);
    printf(")\n");
#endif
}

/* SU=16 */
/* Output point P */
void ECP_BLS12383_rawoutput(ECP_BLS12383 *P)
{
    BIG_384_58 x, z;

#if CURVETYPE_BLS12383!=MONTGOMERY
    BIG_384_58 y;
    FP_BLS12383_redc(x, &(P->x));
    FP_BLS12383_redc(y, &(P->y));
    FP_BLS12383_redc(z, &(P->z));
    printf("(");
    BIG_384_58_output(x);
    printf(",");
    BIG_384_58_output(y);
    printf(",");
    BIG_384_58_output(z);
    printf(")\n");
#else
    FP_BLS12383_redc(x, &(P->x));
    FP_BLS12383_redc(z, &(P->z));
    printf("(");
    BIG_384_58_output(x);
    printf(",");
    BIG_384_58_output(z);
    printf(")\n");
#endif
}

/* SU=88 */
/* Convert P to octet string */
void ECP_BLS12383_toOctet(octet *W, ECP_BLS12383 *P, bool compress)
{
#if CURVETYPE_BLS12383==MONTGOMERY
    BIG_384_58 x; BIG_384_58_zero(x);
    ECP_BLS12383_get(x, P);
    W->len = MODBYTES_384_58;// + 1;
    //W->val[0] = 6;
    BIG_384_58_toBytes(&(W->val[0]), x);
#else
    BIG_384_58 x, y;
    BIG_384_58_zero(x); BIG_384_58_zero(y);
    bool alt=false;
    ECP_BLS12383_affine(P);
    ECP_BLS12383_get(x, y, P);

#if (MBITS-1)%8 <= 4
#ifdef ALLOW_ALT_COMPRESS_BLS12383
    alt=true;
#endif
#endif
    if (alt)
    {
        BIG_384_58_toBytes(&(W->val[0]), x);
        if (compress)
        {
            W->len = MODBYTES_384_58;
            W->val[0]|=0x80;
            if (FP_BLS12383_islarger(&(P->y))==1) W->val[0]|=0x20;
        } else {
            W->len = 2 * MODBYTES_384_58;
            BIG_384_58_toBytes(&(W->val[MODBYTES_384_58]), y);
        }
    } else {
        BIG_384_58_toBytes(&(W->val[1]), x);
        if (compress)
        {
            W->val[0] = 0x02;
            if (FP_BLS12383_sign(&(P->y)) == 1) W->val[0] = 0x03;
            W->len = MODBYTES_384_58 + 1;
        } else {
            W->val[0] = 0x04;
            W->len = 2 * MODBYTES_384_58 + 1;
            BIG_384_58_toBytes(&(W->val[MODBYTES_384_58 + 1]), y);
        }
    }
#endif
}

/* SU=88 */
/* Restore P from octet string */
int ECP_BLS12383_fromOctet(ECP_BLS12383 *P, octet *W)
{
#if CURVETYPE_BLS12383==MONTGOMERY
    BIG_384_58 x;
    BIG_384_58_fromBytes(x, &(W->val[0]));
    if (ECP_BLS12383_set(P, x)) return 1;
    return 0;
#else
    BIG_384_58 x, y;
    bool alt=false;
    int sgn,cmp,typ = W->val[0];

#if (MBITS-1)%8 <= 4
#ifdef ALLOW_ALT_COMPRESS_BLS12383
    alt=true;
#endif
#endif

    if (alt)
    {
        W->val[0]&=0x1f;
        BIG_384_58_fromBytes(x, &(W->val[0]));
        W->val[0]=typ;
        if ((typ&0x80)==0)
        {
            BIG_384_58_fromBytes(y, &(W->val[MODBYTES_384_58]));
            if (ECP_BLS12383_set(P, x, y)) return 1;
            return 0;
        } else {
            if (!ECP_BLS12383_setx(P,x,0)) return 0;
            sgn=(typ&0x20)>>5;
            cmp=FP_BLS12383_islarger(&(P->y));
            if ((sgn==1 && cmp!=1) || (sgn==0 && cmp==1)) ECP_BLS12383_neg(P);
            return 1;
        }

    } else {
        BIG_384_58_fromBytes(x, &(W->val[1]));
        if (typ == 0x04)
        {
            BIG_384_58_fromBytes(y, &(W->val[MODBYTES_384_58 + 1]));
            if (ECP_BLS12383_set(P, x, y)) return 1;
        }
        if (typ == 0x02 || typ == 0x03)
        {
            if (ECP_BLS12383_setx(P, x, typ & 1)) return 1;
        }
    }
    return 0;
#endif
}


/* Set P=2P */
/* SU=272 */
void ECP_BLS12383_dbl(ECP_BLS12383 *P)
{
#if CURVETYPE_BLS12383==WEIERSTRASS
    FP_BLS12383 t0, t1, t2, t3, x3, y3, z3, b;

#if CURVE_A_BLS12383 == 0
        FP_BLS12383_sqr(&t0, &(P->y));                   //t0.sqr();
        FP_BLS12383_mul(&t1, &(P->y), &(P->z));          //t1.mul(z);

        FP_BLS12383_sqr(&t2, &(P->z));                   //t2.sqr();
        FP_BLS12383_add(&(P->z), &t0, &t0);      //z.add(t0);
        FP_BLS12383_norm(&(P->z));                   //z.norm();
        FP_BLS12383_add(&(P->z), &(P->z), &(P->z));  //z.add(z);
        FP_BLS12383_add(&(P->z), &(P->z), &(P->z));  //z.add(z);
        FP_BLS12383_norm(&(P->z));                   //z.norm();

        FP_BLS12383_imul(&t2, &t2, 3 * CURVE_B_I_BLS12383);   //t2.imul(3*ROM.CURVE_B_I);
        FP_BLS12383_mul(&x3, &t2, &(P->z));          //x3.mul(z);

        FP_BLS12383_add(&y3, &t0, &t2);              //y3.add(t2);
        FP_BLS12383_norm(&y3);                       //y3.norm();
        FP_BLS12383_mul(&(P->z), &(P->z), &t1);      //z.mul(t1);

        FP_BLS12383_add(&t1, &t2, &t2);              //t1.add(t2);
        FP_BLS12383_add(&t2, &t2, &t1);              //t2.add(t1);
        FP_BLS12383_sub(&t0, &t0, &t2);              //t0.sub(t2);
        FP_BLS12383_norm(&t0);                       //t0.norm();
        FP_BLS12383_mul(&y3, &y3, &t0);              //y3.mul(t0);
        FP_BLS12383_add(&y3, &y3, &x3);              //y3.add(x3);
        FP_BLS12383_mul(&t1, &(P->x), &(P->y));          //t1.mul(y);

        FP_BLS12383_norm(&t0);                   //x.norm();
        FP_BLS12383_mul(&(P->x), &t0, &t1);      //x.mul(t1);
        FP_BLS12383_add(&(P->x), &(P->x), &(P->x));  //x.add(x);
        FP_BLS12383_norm(&(P->x));                   //x.norm();
        FP_BLS12383_copy(&(P->y), &y3);              //y.copy(y3);
        FP_BLS12383_norm(&(P->y));                   //y.norm();
#else

        if (CURVE_B_I_BLS12383 == 0)                 //if (ROM.CURVE_B_I==0)
            FP_BLS12383_rcopy(&b, CURVE_B_BLS12383);      //b.copy(new FP(new BIG(ROM.CURVE_B)));

        FP_BLS12383_sqr(&t0, &(P->x));                   //t0.sqr();  //1    x^2
        FP_BLS12383_sqr(&t1, &(P->y));                   //t1.sqr();  //2    y^2
        FP_BLS12383_sqr(&t2, &(P->z));                   //t2.sqr();  //3

        FP_BLS12383_mul(&t3, &(P->x), &(P->y));          //t3.mul(y); //4
        FP_BLS12383_add(&t3, &t3, &t3);              //t3.add(t3);
        FP_BLS12383_norm(&t3);                       //t3.norm();//5

        FP_BLS12383_mul(&z3, &(P->z), &(P->x));          //z3.mul(x);   //6
        FP_BLS12383_add(&z3, &z3, &z3);              //z3.add(z3);
        FP_BLS12383_norm(&z3);                       //z3.norm();//7

        if (CURVE_B_I_BLS12383 == 0)                     //if (ROM.CURVE_B_I==0)
            FP_BLS12383_mul(&y3, &t2, &b);           //y3.mul(b); //8
        else
            FP_BLS12383_imul(&y3, &t2, CURVE_B_I_BLS12383); //y3.imul(ROM.CURVE_B_I);

        FP_BLS12383_sub(&y3, &y3, &z3);              //y3.sub(z3); //y3.norm(); //9  ***
        FP_BLS12383_add(&x3, &y3, &y3);              //x3.add(y3);
        FP_BLS12383_norm(&x3);                       //x3.norm();//10

        FP_BLS12383_add(&y3, &y3, &x3);              //y3.add(x3); //y3.norm();//11
        FP_BLS12383_sub(&x3, &t1, &y3);              //x3.sub(y3);
        FP_BLS12383_norm(&x3);                       //x3.norm();//12
        FP_BLS12383_add(&y3, &y3, &t1);              //y3.add(t1);
        FP_BLS12383_norm(&y3);                       //y3.norm();//13
        FP_BLS12383_mul(&y3, &y3, &x3);              //y3.mul(x3); //14
        FP_BLS12383_mul(&x3, &x3, &t3);              //x3.mul(t3); //15
        FP_BLS12383_add(&t3, &t2, &t2);              //t3.add(t2);  //16
        FP_BLS12383_add(&t2, &t2, &t3);              //t2.add(t3); //17

        if (CURVE_B_I_BLS12383 == 0)                 //if (ROM.CURVE_B_I==0)
            FP_BLS12383_mul(&z3, &z3, &b);           //z3.mul(b); //18
        else
            FP_BLS12383_imul(&z3, &z3, CURVE_B_I_BLS12383); //z3.imul(ROM.CURVE_B_I);

        FP_BLS12383_sub(&z3, &z3, &t2);              //z3.sub(t2); //z3.norm();//19
        FP_BLS12383_sub(&z3, &z3, &t0);              //z3.sub(t0);
        FP_BLS12383_norm(&z3);                       //z3.norm();//20  ***
        FP_BLS12383_add(&t3, &z3, &z3);              //t3.add(z3); //t3.norm();//21

        FP_BLS12383_add(&z3, &z3, &t3);              //z3.add(t3);
        FP_BLS12383_norm(&z3);                       //z3.norm(); //22
        FP_BLS12383_add(&t3, &t0, &t0);              //t3.add(t0); //t3.norm(); //23
        FP_BLS12383_add(&t0, &t0, &t3);              //t0.add(t3); //t0.norm();//24
        FP_BLS12383_sub(&t0, &t0, &t2);              //t0.sub(t2);
        FP_BLS12383_norm(&t0);                       //t0.norm();//25

        FP_BLS12383_mul(&t0, &t0, &z3);              //t0.mul(z3);//26
        FP_BLS12383_add(&y3, &y3, &t0);              //y3.add(t0); //y3.norm();//27
        FP_BLS12383_mul(&t0, &(P->y), &(P->z));          //t0.mul(z);//28
        FP_BLS12383_add(&t0, &t0, &t0);              //t0.add(t0);
        FP_BLS12383_norm(&t0);                       //t0.norm(); //29
        FP_BLS12383_mul(&z3, &z3, &t0);              //z3.mul(t0);//30
        FP_BLS12383_sub(&(P->x), &x3, &z3);              //x3.sub(z3); //x3.norm();//31
        FP_BLS12383_add(&t0, &t0, &t0);              //t0.add(t0);
        FP_BLS12383_norm(&t0);                       //t0.norm();//32
        FP_BLS12383_add(&t1, &t1, &t1);              //t1.add(t1);
        FP_BLS12383_norm(&t1);                       //t1.norm();//33
        FP_BLS12383_mul(&(P->z), &t0, &t1);              //z3.mul(t1);//34

        FP_BLS12383_norm(&(P->x));                   //x.norm();
        FP_BLS12383_copy(&(P->y), &y3);              //y.copy(y3);
        FP_BLS12383_norm(&(P->y));                   //y.norm();
        FP_BLS12383_norm(&(P->z));                   //z.norm();
#endif
#endif

#if CURVETYPE_BLS12383==EDWARDS
    /* Not using square for multiplication swap, as (1) it needs more adds, and (2) it triggers more reductions */

    FP_BLS12383 C, D, H, J;

    FP_BLS12383_sqr(&C, &(P->x));                        //C.sqr();

    FP_BLS12383_mul(&(P->x), &(P->x), &(P->y));      //x.mul(y);
    FP_BLS12383_add(&(P->x), &(P->x), &(P->x));      //x.add(x);
    FP_BLS12383_norm(&(P->x));                       //x.norm();

    FP_BLS12383_sqr(&D, &(P->y));                        //D.sqr();

#if CURVE_A_BLS12383 == -1
        FP_BLS12383_neg(&C, &C);             //  C.neg();
#endif
    FP_BLS12383_add(&(P->y), &C, &D);    //y.add(D);
    FP_BLS12383_norm(&(P->y));               //y.norm();
    FP_BLS12383_sqr(&H, &(P->z));            //H.sqr();
    FP_BLS12383_add(&H, &H, &H);             //H.add(H);

    FP_BLS12383_sub(&J, &(P->y), &H);        //J.sub(H);
    FP_BLS12383_norm(&J);                    //J.norm();

    FP_BLS12383_mul(&(P->x), &(P->x), &J);   //x.mul(J);
    FP_BLS12383_sub(&C, &C, &D);             //C.sub(D);
    FP_BLS12383_norm(&C);                    //C.norm();
    FP_BLS12383_mul(&(P->z), &(P->y), &J);   //z.mul(J);
    FP_BLS12383_mul(&(P->y), &(P->y), &C);   //y.mul(C);


#endif

#if CURVETYPE_BLS12383==MONTGOMERY
    FP_BLS12383 A, B, AA, BB, C;

    FP_BLS12383_add(&A, &(P->x), &(P->z));       //A.add(z);
    FP_BLS12383_norm(&A);                    //A.norm();
    FP_BLS12383_sqr(&AA, &A);            //AA.sqr();
    FP_BLS12383_sub(&B, &(P->x), &(P->z));       //B.sub(z);
    FP_BLS12383_norm(&B);                    //B.norm();

    FP_BLS12383_sqr(&BB, &B);            //BB.sqr();
    FP_BLS12383_sub(&C, &AA, &BB);           //C.sub(BB);
    FP_BLS12383_norm(&C);                    //C.norm();
    FP_BLS12383_mul(&(P->x), &AA, &BB);  //x.mul(BB);
    FP_BLS12383_imul(&A, &C, (CURVE_A_BLS12383 + 2) / 4); //A.imul((ROM.CURVE_A+2)/4);

    FP_BLS12383_add(&BB, &BB, &A);           //BB.add(A);
    FP_BLS12383_norm(&BB);                   //BB.norm();
    FP_BLS12383_mul(&(P->z), &BB, &C);   //z.mul(C);

#endif
}

#if CURVETYPE_BLS12383==MONTGOMERY

/* Set P+=Q. W is difference between P and Q and is affine */
void ECP_BLS12383_add(ECP_BLS12383 *P, ECP_BLS12383 *Q, ECP_BLS12383 *W)
{
    FP_BLS12383 A, B, C, D, DA, CB;

    FP_BLS12383_add(&A, &(P->x), &(P->z)); //A.add(z);
    FP_BLS12383_sub(&B, &(P->x), &(P->z)); //B.sub(z);

    FP_BLS12383_add(&C, &(Q->x), &(Q->z)); //C.add(Q.z);

    FP_BLS12383_sub(&D, &(Q->x), &(Q->z)); //D.sub(Q.z);
    FP_BLS12383_norm(&A);            //A.norm();

    FP_BLS12383_norm(&D);            //D.norm();
    FP_BLS12383_mul(&DA, &D, &A);        //DA.mul(A);

    FP_BLS12383_norm(&C);            //C.norm();
    FP_BLS12383_norm(&B);            //B.norm();
    FP_BLS12383_mul(&CB, &C, &B);    //CB.mul(B);

    FP_BLS12383_add(&A, &DA, &CB);   //A.add(CB);
    FP_BLS12383_norm(&A);            //A.norm();
    FP_BLS12383_sqr(&(P->x), &A);        //A.sqr();
    FP_BLS12383_sub(&B, &DA, &CB);   //B.sub(CB);
    FP_BLS12383_norm(&B);            //B.norm();
    FP_BLS12383_sqr(&B, &B);         //B.sqr();

    FP_BLS12383_mul(&(P->z), &(W->x), &B); //z.mul(B);

}

#else

/* Set P+=Q */
/* SU=248 */
void ECP_BLS12383_add(ECP_BLS12383 *P, ECP_BLS12383 *Q)
{
#if CURVETYPE_BLS12383==WEIERSTRASS

    int b3;
    FP_BLS12383 t0, t1, t2, t3, t4, x3, y3, z3, b;

#if CURVE_A_BLS12383 == 0

        b3 = 3 * CURVE_B_I_BLS12383;             //int b=3*ROM.CURVE_B_I;
        FP_BLS12383_mul(&t0, &(P->x), &(Q->x));      //t0.mul(Q.x);
        FP_BLS12383_mul(&t1, &(P->y), &(Q->y));      //t1.mul(Q.y);
        FP_BLS12383_mul(&t2, &(P->z), &(Q->z));      //t2.mul(Q.z);
        FP_BLS12383_add(&t3, &(P->x), &(P->y));      //t3.add(y);
        FP_BLS12383_norm(&t3);                   //t3.norm();

        FP_BLS12383_add(&t4, &(Q->x), &(Q->y));      //t4.add(Q.y);
        FP_BLS12383_norm(&t4);                   //t4.norm();
        FP_BLS12383_mul(&t3, &t3, &t4);          //t3.mul(t4);
        FP_BLS12383_add(&t4, &t0, &t1);          //t4.add(t1);

        FP_BLS12383_sub(&t3, &t3, &t4);          //t3.sub(t4);
        FP_BLS12383_norm(&t3);                   //t3.norm();
        FP_BLS12383_add(&t4, &(P->y), &(P->z));      //t4.add(z);
        FP_BLS12383_norm(&t4);                   //t4.norm();
        FP_BLS12383_add(&x3, &(Q->y), &(Q->z));      //x3.add(Q.z);
        FP_BLS12383_norm(&x3);                   //x3.norm();

        FP_BLS12383_mul(&t4, &t4, &x3);          //t4.mul(x3);
        FP_BLS12383_add(&x3, &t1, &t2);          //x3.add(t2);

        FP_BLS12383_sub(&t4, &t4, &x3);          //t4.sub(x3);
        FP_BLS12383_norm(&t4);                   //t4.norm();
        FP_BLS12383_add(&x3, &(P->x), &(P->z));      //x3.add(z);
        FP_BLS12383_norm(&x3);                   //x3.norm();
        FP_BLS12383_add(&y3, &(Q->x), &(Q->z));      //y3.add(Q.z);
        FP_BLS12383_norm(&y3);                   //y3.norm();
        FP_BLS12383_mul(&x3, &x3, &y3);          //x3.mul(y3);

        FP_BLS12383_add(&y3, &t0, &t2);          //y3.add(t2);
        FP_BLS12383_sub(&y3, &x3, &y3);          //y3.rsub(x3);
        FP_BLS12383_norm(&y3);                   //y3.norm();
        FP_BLS12383_add(&x3, &t0, &t0);          //x3.add(t0);
        FP_BLS12383_add(&t0, &t0, &x3);          //t0.add(x3);
        FP_BLS12383_norm(&t0);                   //t0.norm();
        FP_BLS12383_imul(&t2, &t2, b3);              //t2.imul(b);

        FP_BLS12383_add(&z3, &t1, &t2);          //z3.add(t2);
        FP_BLS12383_norm(&z3);                   //z3.norm();
        FP_BLS12383_sub(&t1, &t1, &t2);          //t1.sub(t2);
        FP_BLS12383_norm(&t1);                   //t1.norm();
        FP_BLS12383_imul(&y3, &y3, b3);              //y3.imul(b);

        FP_BLS12383_mul(&x3, &y3, &t4);          //x3.mul(t4);
        FP_BLS12383_mul(&t2, &t3, &t1);          //t2.mul(t1);
        FP_BLS12383_sub(&(P->x), &t2, &x3);          //x3.rsub(t2);
        FP_BLS12383_mul(&y3, &y3, &t0);          //y3.mul(t0);
        FP_BLS12383_mul(&t1, &t1, &z3);          //t1.mul(z3);
        FP_BLS12383_add(&(P->y), &y3, &t1);          //y3.add(t1);
        FP_BLS12383_mul(&t0, &t0, &t3);          //t0.mul(t3);
        FP_BLS12383_mul(&z3, &z3, &t4);          //z3.mul(t4);
        FP_BLS12383_add(&(P->z), &z3, &t0);          //z3.add(t0);

        FP_BLS12383_norm(&(P->x));               //x.norm();
        FP_BLS12383_norm(&(P->y));               //y.norm();
        FP_BLS12383_norm(&(P->z));               //z.norm();
#else

        if (CURVE_B_I_BLS12383 == 0)             //if (ROM.CURVE_B_I==0)
            FP_BLS12383_rcopy(&b, CURVE_B_BLS12383);  //b.copy(new FP(new BIG(ROM.CURVE_B)));

        FP_BLS12383_mul(&t0, &(P->x), &(Q->x));      //t0.mul(Q.x); //1
        FP_BLS12383_mul(&t1, &(P->y), &(Q->y));      //t1.mul(Q.y); //2
        FP_BLS12383_mul(&t2, &(P->z), &(Q->z));      //t2.mul(Q.z); //3

        FP_BLS12383_add(&t3, &(P->x), &(P->y));      //t3.add(y);
        FP_BLS12383_norm(&t3);                   //t3.norm(); //4
        FP_BLS12383_add(&t4, &(Q->x), &(Q->y));      //t4.add(Q.y);
        FP_BLS12383_norm(&t4);                   //t4.norm();//5
        FP_BLS12383_mul(&t3, &t3, &t4);          //t3.mul(t4);//6

        FP_BLS12383_add(&t4, &t0, &t1);          //t4.add(t1); //t4.norm(); //7
        FP_BLS12383_sub(&t3, &t3, &t4);          //t3.sub(t4);
        FP_BLS12383_norm(&t3);                   //t3.norm(); //8
        FP_BLS12383_add(&t4, &(P->y), &(P->z));      //t4.add(z);
        FP_BLS12383_norm(&t4);                   //t4.norm();//9
        FP_BLS12383_add(&x3, &(Q->y), &(Q->z));      //x3.add(Q.z);
        FP_BLS12383_norm(&x3);                   //x3.norm();//10
        FP_BLS12383_mul(&t4, &t4, &x3);          //t4.mul(x3); //11
        FP_BLS12383_add(&x3, &t1, &t2);          //x3.add(t2); //x3.norm();//12

        FP_BLS12383_sub(&t4, &t4, &x3);          //t4.sub(x3);
        FP_BLS12383_norm(&t4);                   //t4.norm();//13
        FP_BLS12383_add(&x3, &(P->x), &(P->z));      //x3.add(z);
        FP_BLS12383_norm(&x3);                   //x3.norm(); //14
        FP_BLS12383_add(&y3, &(Q->x), &(Q->z));      //y3.add(Q.z);
        FP_BLS12383_norm(&y3);                   //y3.norm();//15

        FP_BLS12383_mul(&x3, &x3, &y3);          //x3.mul(y3); //16
        FP_BLS12383_add(&y3, &t0, &t2);          //y3.add(t2); //y3.norm();//17

        FP_BLS12383_sub(&y3, &x3, &y3);          //y3.rsub(x3);
        FP_BLS12383_norm(&y3);                   //y3.norm(); //18

        if (CURVE_B_I_BLS12383 == 0)             //if (ROM.CURVE_B_I==0)
            FP_BLS12383_mul(&z3, &t2, &b);       //z3.mul(b); //18
        else
            FP_BLS12383_imul(&z3, &t2, CURVE_B_I_BLS12383); //z3.imul(ROM.CURVE_B_I);

        FP_BLS12383_sub(&x3, &y3, &z3);          //x3.sub(z3);
        FP_BLS12383_norm(&x3);                   //x3.norm(); //20
        FP_BLS12383_add(&z3, &x3, &x3);          //z3.add(x3); //z3.norm(); //21

        FP_BLS12383_add(&x3, &x3, &z3);          //x3.add(z3); //x3.norm(); //22
        FP_BLS12383_sub(&z3, &t1, &x3);          //z3.sub(x3);
        FP_BLS12383_norm(&z3);                   //z3.norm(); //23
        FP_BLS12383_add(&x3, &x3, &t1);          //x3.add(t1);
        FP_BLS12383_norm(&x3);                   //x3.norm(); //24

        if (CURVE_B_I_BLS12383 == 0)             //if (ROM.CURVE_B_I==0)
            FP_BLS12383_mul(&y3, &y3, &b);       //y3.mul(b); //18
        else
            FP_BLS12383_imul(&y3, &y3, CURVE_B_I_BLS12383); //y3.imul(ROM.CURVE_B_I);

        FP_BLS12383_add(&t1, &t2, &t2);          //t1.add(t2); //t1.norm();//26
        FP_BLS12383_add(&t2, &t2, &t1);          //t2.add(t1); //t2.norm();//27

        FP_BLS12383_sub(&y3, &y3, &t2);          //y3.sub(t2); //y3.norm(); //28

        FP_BLS12383_sub(&y3, &y3, &t0);          //y3.sub(t0);
        FP_BLS12383_norm(&y3);                   //y3.norm(); //29
        FP_BLS12383_add(&t1, &y3, &y3);          //t1.add(y3); //t1.norm();//30
        FP_BLS12383_add(&y3, &y3, &t1);          //y3.add(t1);
        FP_BLS12383_norm(&y3);                   //y3.norm(); //31

        FP_BLS12383_add(&t1, &t0, &t0);          //t1.add(t0); //t1.norm(); //32
        FP_BLS12383_add(&t0, &t0, &t1);          //t0.add(t1); //t0.norm();//33
        FP_BLS12383_sub(&t0, &t0, &t2);          //t0.sub(t2);
        FP_BLS12383_norm(&t0);                   //t0.norm();//34

        FP_BLS12383_mul(&t1, &t4, &y3);          //t1.mul(y3);//35
        FP_BLS12383_mul(&t2, &t0, &y3);          //t2.mul(y3);//36
        FP_BLS12383_mul(&y3, &x3, &z3);          //y3.mul(z3);//37
        FP_BLS12383_add(&(P->y), &y3, &t2);          //y3.add(t2); //y3.norm();//38
        FP_BLS12383_mul(&x3, &x3, &t3);          //x3.mul(t3);//39
        FP_BLS12383_sub(&(P->x), &x3, &t1);          //x3.sub(t1);//40
        FP_BLS12383_mul(&z3, &z3, &t4);          //z3.mul(t4);//41

        FP_BLS12383_mul(&t1, &t3, &t0);          //t1.mul(t0);//42
        FP_BLS12383_add(&(P->z), &z3, &t1);          //z3.add(t1);
        FP_BLS12383_norm(&(P->x));               //x.norm();

        FP_BLS12383_norm(&(P->y));               //y.norm();
        FP_BLS12383_norm(&(P->z));               //z.norm();
#endif

#else
    FP_BLS12383 A, B, C, D, E, F, G, b;

    FP_BLS12383_mul(&A, &(P->z), &(Q->z));   //A.mul(Q.z);
    FP_BLS12383_sqr(&B, &A);                 //B.sqr();
    FP_BLS12383_mul(&C, &(P->x), &(Q->x));   //C.mul(Q.x);
    FP_BLS12383_mul(&D, &(P->y), &(Q->y));   //D.mul(Q.y);
    FP_BLS12383_mul(&E, &C, &D);             //E.mul(D);

    if (CURVE_B_I_BLS12383 == 0)         //if (ROM.CURVE_B_I==0)
    {
        FP_BLS12383_rcopy(&b, CURVE_B_BLS12383);  //FP b=new FP(new BIG(ROM.CURVE_B));
        FP_BLS12383_mul(&E, &E, &b);         //E.mul(b);
    }
    else
        FP_BLS12383_imul(&E, &E, CURVE_B_I_BLS12383); //E.imul(ROM.CURVE_B_I);

    FP_BLS12383_sub(&F, &B, &E);         //F.sub(E);
    FP_BLS12383_add(&G, &B, &E);         //G.add(E);

#if CURVE_A_BLS12383 == 1
        FP_BLS12383_sub(&E, &D, &C);     //E.sub(C);
#endif
    FP_BLS12383_add(&C, &C, &D);         //C.add(D);
    FP_BLS12383_add(&B, &(P->x), &(P->y));   //B.add(y);

    FP_BLS12383_add(&D, &(Q->x), &(Q->y));   //D.add(Q.y);
    FP_BLS12383_norm(&B);                //B.norm();
    FP_BLS12383_norm(&D);                //D.norm();
    FP_BLS12383_mul(&B, &B, &D);         //B.mul(D);
    FP_BLS12383_sub(&B, &B, &C);         //B.sub(C);
    FP_BLS12383_norm(&B);                //B.norm();
    FP_BLS12383_norm(&F);                //F.norm();
    FP_BLS12383_mul(&B, &B, &F);         //B.mul(F);
    FP_BLS12383_mul(&(P->x), &A, &B); //x.mul(B);
    FP_BLS12383_norm(&G);                //G.norm();

#if CURVE_A_BLS12383 == 1
        FP_BLS12383_norm(&E);            //E.norm();
        FP_BLS12383_mul(&C, &E, &G);     //C.mul(G);
#endif
#if CURVE_A_BLS12383 == -1
        FP_BLS12383_norm(&C);            //C.norm();
        FP_BLS12383_mul(&C, &C, &G);     //C.mul(G);
#endif
    FP_BLS12383_mul(&(P->y), &A, &C); //y.mul(C);
    FP_BLS12383_mul(&(P->z), &F, &G); //z.mul(G);

#endif
}

/* Set P-=Q */
/* SU=16 */
void  ECP_BLS12383_sub(ECP_BLS12383 *P, ECP_BLS12383 *Q)
{
    ECP_BLS12383 NQ;
    ECP_BLS12383_copy(&NQ, Q);
    ECP_BLS12383_neg(&NQ);
    ECP_BLS12383_add(P, &NQ);
}

#endif

#if CURVETYPE_BLS12383!=MONTGOMERY
/* constant time multiply by small integer of length bts - use ladder */
void ECP_BLS12383_pinmul(ECP_BLS12383 *P, int e, int bts)
{
    int i, b;
    ECP_BLS12383 R0, R1;

    ECP_BLS12383_affine(P);
    ECP_BLS12383_inf(&R0);
    ECP_BLS12383_copy(&R1, P);

    for (i = bts - 1; i >= 0; i--)
    {
        b = (e >> i) & 1;
        ECP_BLS12383_copy(P, &R1);
        ECP_BLS12383_add(P, &R0);
        ECP_BLS12383_cswap(&R0, &R1, b);
        ECP_BLS12383_copy(&R1, P);
        ECP_BLS12383_dbl(&R0);
        ECP_BLS12383_cswap(&R0, &R1, b);
    }
    ECP_BLS12383_copy(P, &R0);
}
#endif

// Point multiplication, multiplies a point P by a scalar e
// This code has no inherent awareness of the order of the curve, or the order of the point.
// The order of the curve will be h.r, where h is a cofactor, and r is a large prime
// Typically P will be of order r (but not always), and typically e will be less than r (but not always)
// A problem can arise if a secret e is a few bits less than r, as the leading zeros in e will leak via a timing attack
// The secret e may however be greater than r (see RFC7748 which combines elimination of a small cofactor h with the point multiplication, using an e>r)
// Our solution is to use as a multiplier an e, whose length in bits is that of the logical OR of e and r, hence allowing e>r while forcing inclusion of leading zeros if e<r. 
// The point multiplication methods used will process leading zeros correctly.

// So this function leaks information about the length of e...
void ECP_BLS12383_mul(ECP_BLS12383 *P,BIG_384_58 e)
{
    ECP_BLS12383_clmul(P,e,e);
}

// .. but this one does not (typically set maxe=r)
// Set P=e*P 
void ECP_BLS12383_clmul(ECP_BLS12383 *P, BIG_384_58 e, BIG_384_58 maxe)
{
    int max;
    BIG_384_58 cm;
#if CURVETYPE_BLS12383==MONTGOMERY
    /* Montgomery ladder */
    int nb, i, b;
    ECP_BLS12383 R0, R1, D;
    BIG_384_58_or(cm,e,maxe);
    max=BIG_384_58_nbits(cm);

    if (ECP_BLS12383_isinf(P)) return;
    if (BIG_384_58_iszilch(e))
    {
        ECP_BLS12383_inf(P);
        return;
    }

    ECP_BLS12383_copy(&R0, P);
    ECP_BLS12383_copy(&R1, P);
    ECP_BLS12383_dbl(&R1);

    ECP_BLS12383_copy(&D, P);
    ECP_BLS12383_affine(&D);

    nb = max;
    for (i = nb - 2; i >= 0; i--)
    {
        b = BIG_384_58_bit(e, i);
        ECP_BLS12383_copy(P, &R1);
        ECP_BLS12383_add(P, &R0, &D);
        ECP_BLS12383_cswap(&R0, &R1, b);
        ECP_BLS12383_copy(&R1, P);
        ECP_BLS12383_dbl(&R0);

        ECP_BLS12383_cswap(&R0, &R1, b);
    }

    ECP_BLS12383_copy(P, &R0);

#else
    /* fixed size windows */
    int i, nb, s, ns;
    BIG_384_58 mt, t;
    ECP_BLS12383 Q, W[8], C;
    sign8 w[1 + (NLEN_384_58 * BASEBITS_384_58 + 3) / 4];
    BIG_384_58_or(cm,e,maxe);
    max=BIG_384_58_nbits(cm);

    if (ECP_BLS12383_isinf(P)) return;
    if (BIG_384_58_iszilch(e))
    {
        ECP_BLS12383_inf(P);
        return;
    }

    /* precompute table */

    ECP_BLS12383_copy(&Q, P);
    ECP_BLS12383_dbl(&Q);

    ECP_BLS12383_copy(&W[0], P);

    for (i = 1; i < 8; i++)
    {
        ECP_BLS12383_copy(&W[i], &W[i - 1]);
        ECP_BLS12383_add(&W[i], &Q);
    }

//printf("W[1]= ");ECP_output(&W[1]); printf("\n");

    /* make exponent odd - add 2P if even, P if odd */
    BIG_384_58_copy(t, e);
    s = BIG_384_58_parity(t);
    BIG_384_58_inc(t, 1);
    BIG_384_58_norm(t);
    ns = BIG_384_58_parity(t);
    BIG_384_58_copy(mt, t);
    BIG_384_58_inc(mt, 1);
    BIG_384_58_norm(mt);
    BIG_384_58_cmove(t, mt, s);
    ECP_BLS12383_cmove(&Q, P, ns);
    ECP_BLS12383_copy(&C, &Q);

    nb = 1 + (max + 3) / 4;

    /* convert exponent to signed 4-bit window */
    for (i = 0; i < nb; i++)
    {
        w[i] = BIG_384_58_lastbits(t, 5) - 16;
        BIG_384_58_dec(t, w[i]);
        BIG_384_58_norm(t);
        BIG_384_58_fshr(t, 4);
    }
    w[nb] = BIG_384_58_lastbits(t, 5);

    //ECP_BLS12383_copy(P, &W[(w[nb] - 1) / 2]);
    ECP_BLS12383_select(P, W, w[i]);
    for (i = nb - 1; i >= 0; i--)
    {
        ECP_BLS12383_select(&Q, W, w[i]);
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_add(P, &Q);
    }
    ECP_BLS12383_sub(P, &C); /* apply correction */
#endif
}

#if CURVETYPE_BLS12383!=MONTGOMERY

// Generic multi-multiplication, fixed 4-bit window, P=Sigma e_i*X_i
void ECP_BLS12383_muln(ECP_BLS12383 *P,int n,ECP_BLS12383 X[],BIG_384_58 e[])
{
    int i,j,k,nb;
    BIG_384_58 t,mt;
    ECP_BLS12383 S,R,B[16];
    ECP_BLS12383_inf(P);

    BIG_384_58_copy(mt,e[0]);  BIG_384_58_norm(mt);
    for (i=1;i<n;i++)
    { // find biggest
        BIG_384_58_copy(t,e[i]); BIG_384_58_norm(t);
        k=BIG_384_58_comp(t,mt);
        BIG_384_58_cmove(mt,t,(k+1)/2);
    }
    nb=(BIG_384_58_nbits(mt)+3)/4;
    for (int i=nb-1;i>=0;i--)
    { // Pippenger's algorithm
        for (j=0;j<16;j++)
            ECP_BLS12383_inf(&B[j]);
        for (j=0;j<n;j++)
        {
            BIG_384_58_copy(mt,e[j]); BIG_384_58_norm(mt);
            BIG_384_58_shr(mt,4*i);
            k=BIG_384_58_lastbits(mt,4);
            ECP_BLS12383_add(&B[k],&X[j]);
        }
        ECP_BLS12383_inf(&R); ECP_BLS12383_inf(&S);
        for (j=15;j>=1;j--)
        {
            ECP_BLS12383_add(&R,&B[j]);
            ECP_BLS12383_add(&S,&R);
        }
        for (j=0;j<4;j++)
            ECP_BLS12383_dbl(P);
        ECP_BLS12383_add(P,&S);
    }
}

/* Set P=eP+fQ double multiplication */
/* constant time - as useful for GLV method in pairings */
/* SU=456 */

void ECP_BLS12383_mul2(ECP_BLS12383 *P, ECP_BLS12383 *Q, BIG_384_58 e, BIG_384_58 f)
{
    BIG_384_58 te, tf, mt;
    ECP_BLS12383 S, T, W[8], C;
    sign8 w[1 + (NLEN_384_58 * BASEBITS_384_58 + 1) / 2];
    int i, a, b, s, ns, nb;

    BIG_384_58_copy(te, e);
    BIG_384_58_copy(tf, f);

    /* precompute table */
    ECP_BLS12383_copy(&W[1], P);
    ECP_BLS12383_sub(&W[1], Q); /* P+Q */
    ECP_BLS12383_copy(&W[2], P);
    ECP_BLS12383_add(&W[2], Q); /* P-Q */
    ECP_BLS12383_copy(&S, Q);
    ECP_BLS12383_dbl(&S);  /* S=2Q */
    ECP_BLS12383_copy(&W[0], &W[1]);
    ECP_BLS12383_sub(&W[0], &S);
    ECP_BLS12383_copy(&W[3], &W[2]);
    ECP_BLS12383_add(&W[3], &S);
    ECP_BLS12383_copy(&T, P);
    ECP_BLS12383_dbl(&T); /* T=2P */
    ECP_BLS12383_copy(&W[5], &W[1]);
    ECP_BLS12383_add(&W[5], &T);
    ECP_BLS12383_copy(&W[6], &W[2]);
    ECP_BLS12383_add(&W[6], &T);
    ECP_BLS12383_copy(&W[4], &W[5]);
    ECP_BLS12383_sub(&W[4], &S);
    ECP_BLS12383_copy(&W[7], &W[6]);
    ECP_BLS12383_add(&W[7], &S);

    /* if multiplier is odd, add 2, else add 1 to multiplier, and add 2P or P to correction */

    s = BIG_384_58_parity(te);
    BIG_384_58_inc(te, 1);
    BIG_384_58_norm(te);
    ns = BIG_384_58_parity(te);
    BIG_384_58_copy(mt, te);
    BIG_384_58_inc(mt, 1);
    BIG_384_58_norm(mt);
    BIG_384_58_cmove(te, mt, s);
    ECP_BLS12383_cmove(&T, P, ns);
    ECP_BLS12383_copy(&C, &T);

    s = BIG_384_58_parity(tf);
    BIG_384_58_inc(tf, 1);
    BIG_384_58_norm(tf);
    ns = BIG_384_58_parity(tf);
    BIG_384_58_copy(mt, tf);
    BIG_384_58_inc(mt, 1);
    BIG_384_58_norm(mt);
    BIG_384_58_cmove(tf, mt, s);
    ECP_BLS12383_cmove(&S, Q, ns);
    ECP_BLS12383_add(&C, &S);

    BIG_384_58_add(mt, te, tf);
    BIG_384_58_norm(mt);
    nb = 1 + (BIG_384_58_nbits(mt) + 1) / 2;

    /* convert exponent to signed 2-bit window */
    for (i = 0; i < nb; i++)
    {
        a = BIG_384_58_lastbits(te, 3) - 4;
        BIG_384_58_dec(te, a);
        BIG_384_58_norm(te);
        BIG_384_58_fshr(te, 2);
        b = BIG_384_58_lastbits(tf, 3) - 4;
        BIG_384_58_dec(tf, b);
        BIG_384_58_norm(tf);
        BIG_384_58_fshr(tf, 2);
        w[i] = 4 * a + b;
    }
    w[nb] = (4 * BIG_384_58_lastbits(te, 3) + BIG_384_58_lastbits(tf, 3));

    //ECP_BLS12383_copy(P, &W[(w[nb] - 1) / 2]);
    ECP_BLS12383_select(P, W, w[i]);
    for (i = nb - 1; i >= 0; i--)
    {
        ECP_BLS12383_select(&T, W, w[i]);
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_dbl(P);
        ECP_BLS12383_add(P, &T);
    }
    ECP_BLS12383_sub(P, &C); /* apply correction */
}

#endif

int ECP_BLS12383_generator(ECP_BLS12383 *G)
{
    BIG_384_58 x, y;
    BIG_384_58_rcopy(x, CURVE_Gx_BLS12383);
#if CURVETYPE_BLS12383!=MONTGOMERY
    BIG_384_58_rcopy(y, CURVE_Gy_BLS12383);
    return ECP_BLS12383_set(G, x, y);
#else
    return ECP_BLS12383_set(G, x);
#endif
}

#ifdef HAS_MAIN

int main()
{
    int i;
    ECP_BLS12383 G, P;
    csprng RNG;
    BIG_384_58 r, s, x, y, b, m, w, q;
    BIG_384_58_rcopy(x, CURVE_Gx);
#if CURVETYPE_BLS12383!=MONTGOMERY
    BIG_384_58_rcopy(y, CURVE_Gy);
#endif
    BIG_384_58_rcopy(m, Modulus_BLS12383);

    printf("x= ");
    BIG_384_58_output(x);
    printf("\n");
#if CURVETYPE_BLS12383!=MONTGOMERY
    printf("y= ");
    BIG_384_58_output(y);
    printf("\n");
#endif
    RNG_seed(&RNG, 3, "abc");

#if CURVETYPE_BLS12383!=MONTGOMERY
    ECP_BLS12383_set(&G, x, y);
#else
    ECP_BLS12383_set(&G, x);
#endif
    if (ECP_BLS12383_isinf(&G)) printf("Failed to set - point not on curve\n");
    else printf("set success\n");

    ECP_BLS12383_output(&G);

    BIG_384_58_rcopy(r, CURVE_Order); //BIG_dec(r,7);
    printf("r= ");
    BIG_384_58_output(r);
    printf("\n");

    ECP_BLS12383_copy(&P, &G);

    ECP_BLS12383_mul(&P, r);

    ECP_BLS12383_output(&P);
//exit(0);
    BIG_384_58_randomnum(w, &RNG);
    BIG_384_58_mod(w, r);

    ECP_BLS12383_copy(&P, &G);
    ECP_BLS12383_mul(&P, w);

    ECP_BLS12383_output(&P);

    return 0;
}

#endif
