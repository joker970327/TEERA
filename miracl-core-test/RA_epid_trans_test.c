#include "RA_curve.h"

int main(){
    initiate();

    G1 g1;
    G2 g2;
    GT gt;
    random_G1(&g1);
    random_G2(&g2);
    pairing(&gt,&g2,&g1);

    Big A;
    Big B;
    Big C;
    random_Big(A);
    random_Big(B);
    modadd(C,A,B,CURVE_Order);

    FILE *fp=fopen("RA_data.txt","w");

    char g1_s[2*MODBYTES+1];
    octet g1_o={0,sizeof(g1_s),g1_s};
    G1_toOctet(&g1_o,&g1,false);
    printf("g1:\n");
    display_G1(&g1);
    for(int i=0;i<g1_o.len;i++){
        // unsigned char ch=g1_o.val[i];
        unsigned char ch=g1_s[i];
        fprintf(fp,"%02x",ch);
    }
    fprintf(fp,"\n");

    char g2_s[4*MODBYTES+1];
    octet g2_o={0,sizeof(g2_s),g2_s};
    G2_toOctet(&g2_o,&g2,false);
    printf("g2:\n");
    display_G2(&g2);
    for(int i=0;i<g2_o.len;i++){
        // unsigned char ch=g2_o.val[i];
        unsigned char ch=g2_s[i];
        fprintf(fp,"%02x",ch);
    }
    fprintf(fp,"\n");

    char gt_s[12*MODBYTES+1];
    octet gt_o={0,sizeof(gt_s),gt_s};
    GT_toOctet(&gt_o,&gt);
    printf("gt:\n");
    display_GT(&gt);
    for(int i=0;i<gt_o.len;i++){
        // unsigned char ch=g2_o.val[i];
        unsigned char ch=gt_s[i];
        fprintf(fp,"%02x",ch);
    }
    fprintf(fp,"\n");

    char A_s[MODBYTES];
    octet A_o={MODBYTES,sizeof(A_s),A_s};
    BIG_toBytes(A_o.val,A);
    printf("A:\n");
    display_Big(A);
    for(int i=0;i<A_o.len;i++){
        // unsigned char ch=g2_o.val[i];
        unsigned char ch=A_s[i];
        fprintf(fp,"%02x",ch);
    }
    fprintf(fp,"\n");

    char B_s[MODBYTES];
    octet B_o={MODBYTES,sizeof(B_s),B_s};
    BIG_toBytes(B_o.val,B);
    printf("B:\n");
    display_Big(B);
    for(int i=0;i<B_o.len;i++){
        // unsigned char ch=g2_o.val[i];
        unsigned char ch=B_s[i];
        fprintf(fp,"%02x",ch);
    }
    fprintf(fp,"\n");

    char C_s[MODBYTES];
    octet C_o={MODBYTES,sizeof(C_s),C_s};
    BIG_toBytes(C_o.val,C);
    printf("C:\n");
    display_Big(C);
    for(int i=0;i<C_o.len;i++){
        // unsigned char ch=g2_o.val[i];
        unsigned char ch=C_s[i];
        fprintf(fp,"%02x",ch);
    }
    fprintf(fp,"\n");

    fclose(fp);

    fp=fopen("RA_data.txt","r");
// reading
    printf("[reading...]\n");

    G1 g1_r;
    G2 g2_r;
    GT gt_r,gt_c;
    Big A_r,B_r,C_r,C_c;

    //G1
    char g1_o_s_r[2*MODBYTES+1]={0};
    char g1_s_r[2*sizeof(g1_o_s_r)+3]={0};//包含\n和\0
    octet g1_o_r={sizeof(g1_o_s_r),sizeof(g1_o_s_r),g1_o_s_r};
    fgets(g1_s_r,sizeof(g1_s_r),fp);
    OCT_fromHex(&g1_o_r,g1_s_r);
    G1_fromOctet(&g1_r,&g1_o_r);
    printf("G1 from file:\n");
    display_G1(&g1_r);
    if(G1_equals(&g1,&g1_r))printf("G1 read correct!\n");
    else printf("G1 read error!\n");

    //G2
    char g2_o_s_r[4*MODBYTES+1]={0};
    char g2_s_r[2*sizeof(g2_o_s_r)+3]={0};
    octet g2_o_r={sizeof(g2_o_s_r),sizeof(g2_o_s_r),g2_o_s_r};
    fgets(g2_s_r,sizeof(g2_s_r),fp);
    OCT_fromHex(&g2_o_r,g2_s_r);
    G2_fromOctet(&g2_r,&g2_o_r);
    printf("G2 from file:\n");
    display_G2(&g2_r);
    if(G2_equals(&g2,&g2_r))printf("G2 read correct!\n");
    else printf("G2 read error!\n");

    //GT
    char gt_o_s_r[12*MODBYTES+1]={0};
    char gt_s_r[2*sizeof(gt_o_s_r)+3]={0};
    octet gt_o_r={sizeof(gt_o_s_r),sizeof(gt_o_s_r),gt_o_s_r};
    fgets(gt_s_r,sizeof(gt_s_r),fp);
    OCT_fromHex(&gt_o_r,gt_s_r);
    GT_fromOctet(&gt_r,&gt_o_r);
    printf("GT from file:\n");
    display_GT(&gt_r);
    if(GT_equals(&gt,&gt_r))printf("GT read correct!\n");
    else printf("GT read error!\n");

    //A
    char A_o_s_r[MODBYTES]={0};
    char A_s_r[2*sizeof(A_o_s_r)+3]={0};
    octet A_o_r={MODBYTES,sizeof(A_o_s_r),A_o_s_r};
    fgets(A_s_r,sizeof(A_s_r),fp);
    OCT_fromHex(&A_o_r,A_s_r);
    BIG_fromBytes(A_r,A_o_r.val);
    printf("A from file:\n");
    display_Big(A_r);
    if(BIG_comp(A,A_r)==0)printf("A read correct!\n");
    else printf("A read error!\n");

    //B
    char B_o_s_r[MODBYTES];
    char B_s_r[2*sizeof(B_o_s_r)+3];
    octet B_o_r={MODBYTES,sizeof(B_o_s_r),B_o_s_r};
    fgets(B_s_r,sizeof(B_s_r),fp);
    OCT_fromHex(&B_o_r,B_s_r);
    BIG_fromBytes(B_r,B_o_r.val);
    printf("B from file:\n");
    display_Big(B_r);
    if(BIG_comp(B,B_r)==0)printf("B read correct!\n");
    else printf("B read error!\n");

    //C
    char C_o_s_r[MODBYTES];
    char C_s_r[2*sizeof(C_o_s_r)+3];
    octet C_o_r={MODBYTES,sizeof(C_o_s_r),C_o_s_r};
    fgets(C_s_r,sizeof(C_s_r),fp);
    OCT_fromHex(&C_o_r,C_s_r);
    BIG_fromBytes(C_r,C_o_r.val);
    printf("C from file:\n");
    display_Big(C_r);
    if(BIG_comp(C,C_r)==0)printf("C read correct!\n");
    else printf("C read error!\n");

    //计算GT
    pairing(&gt_c,&g2_r,&g1_r);
    printf("GT calculate:\n");
    display_GT(&gt_c);
    if(GT_equals(&gt_c,&gt)){
        printf("GT calculate correct!\n");
    }
    else{
        printf("GT calculate error!\n");
    }

    //计算C
    modadd(C_c,A_r,B_r,CURVE_Order);
    printf("C calculate:\n");
    display_Big(C_c);
    if(BIG_comp(C_c,C)==0){
        printf("C calculate correct!\n");
    }
    else{
        printf("C calculate error!\n");
    }
}