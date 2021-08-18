#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

typedef struct _b10rsa_st
{
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB10_RSA;

BOB10_RSA *BOB10_RSA_new();
int BOB10_RSA_free(BOB10_RSA *b10rsa);
int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits);
int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa);
int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa);
BIGNUM *GenProbPrime(int pBits);
int MillerRabin(BIGNUM *p);
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);

BOB10_RSA *BOB10_RSA_new()
{
    BOB10_RSA *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
        fprintf(stderr, "Error : fail to BOB10_RSA_new()");
        return NULL;
    }

    ret->e = BN_new();
    ret->d = BN_new();
    ret->n = BN_new();

    return ret;
}

int BOB10_RSA_free(BOB10_RSA *b10rsa)
{
    if (b10rsa == NULL) return 1;
    if (b10rsa->e != NULL) BN_free(b10rsa->e);
    if (b10rsa->d != NULL) BN_free(b10rsa->d);
    if (b10rsa->n != NULL) BN_free(b10rsa->n);
    OPENSSL_free(b10rsa);

    return 1;
}

int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits)
{
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();

    BIGNUM *pp = BN_new();
    BIGNUM *pq = BN_new();
    BIGNUM *pn = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *zero = BN_new();

    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *gcd = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // define p, q
    unsigned int pBits = nBits / 2;

    p = GenProbPrime(pBits);
    q = GenProbPrime(pBits);

    //BN_hex2bn(&p, "C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7");
    //BN_hex2bn(&q, "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F");

    // calculate n
    BN_mul(n, p, q, ctx);

    // calculate pn
    BN_one(one);
    BN_sub(pp, p, one);
    BN_sub(pq, q, one);
    BN_mul(pn, pp, pq, ctx);

    // calculate e
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    BN_hex2bn(&e, "2");

    while (BN_cmp(e,pn) == -1){
        gcd = XEuclid(x,y,e,pn);
        if (BN_is_one(gcd)) break;
        BN_add(e, e, one);
    }

    // calculate d
    BN_copy(d,x);

    BN_copy(b10rsa->e,e);
    BN_copy(b10rsa->d,d);
    BN_copy(b10rsa->n,n);
    return 1;
}

int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa)
{
    ExpMod(c,m,b10rsa->e,b10rsa->n);
    return 1;
}

int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa)
{
    ExpMod(m,c,b10rsa->d,b10rsa->n);
    return 1;
}

BIGNUM *GenProbPrime(int pBits)
{
    BIGNUM *p = BN_new();

    while (1){
        BN_rand(p, pBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        if (MillerRabin(p) == 1)  break;
    }
    return p;
}

int MillerRabin(BIGNUM *p)
{
    BIGNUM *a = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *bound = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    int k = 0;
    int flag = 0;

    BN_one(one);
    BN_hex2bn(&two,"2");

    if (BN_cmp(p,two) == 0) return 1;

    BN_mod(rem,p,two,ctx);
    if (BN_is_zero(rem)) return 0;

    BN_sub(bound,p,one);
    BN_copy(g,bound);

    BN_mod(rem,g,two,ctx);

    while (BN_is_zero(rem)){
        k++;
        BN_div(g,rem,g,two,ctx);
    }

    BN_rand_range(a,bound);
    while(BN_cmp(a,two) == -1)
        BN_rand_range(a,bound);

    ExpMod(x,a,g,p);
    if (BN_is_one(x)) return 1;
    if (BN_cmp(x,bound) == 0) return 1;

    while (k > 1){
        ExpMod(x,x,two,p);
        if (BN_is_one(x)) return 0;
        if (BN_cmp(x,bound) == 0) return 1;
        k--;
    }

    return 0;
}

// r = a**e mod m
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
    BIGNUM *res = BN_new();
    BIGNUM* rem = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *mul = BN_new();
    BIGNUM *two = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    BN_one(res);
    BN_mod(mul, a, m, ctx);
    BN_copy(q, e);
    BN_hex2bn(&two, "2");

    while (!BN_is_zero(q)){
        BN_div(q, rem, q, two, ctx);

        if (BN_is_one(rem)) 
            BN_mod_mul(res, res, mul, m, ctx);

        BN_mod_mul(mul, mul, mul, m, ctx);
    }

    BN_copy(r, res);
    return 1;
}


BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
    BIGNUM *r1 = BN_new();
    BIGNUM *r2 = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *s2 = BN_new();
    BIGNUM *t1 = BN_new();
    BIGNUM *t2 = BN_new();

    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *zero = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *tmp = BN_new();

    BN_copy(r1, a);
    BN_copy(r2, b);
    BN_one(s1);
    BN_zero(s2);
    BN_zero(t1);
    BN_one(t2);

    while(!BN_is_zero(r2)){
        BN_div(q,r,r1,r2,ctx);
        BN_copy(r1, r2);
        BN_copy(r2, r);

        BN_mul(tmp,q,s2,ctx);
        BN_sub(x,s1,tmp);
        BN_copy(s1, s2);
        BN_copy(s2, x);

        BN_mul(tmp,q,t2,ctx);
        BN_sub(y,t1,tmp);
        BN_copy(t1, t2);
        BN_copy(t2, y);
    }
    BN_copy(x, s1);
    BN_copy(y, t1);

    if (BN_is_one(r1)){
        BN_zero(zero);
        if (BN_cmp(x,zero) == -1){
            BN_add(x,x,b);
        }
    }

    return r1;
}

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main (int argc, char *argv[])
{
    BOB10_RSA *b10rsa = BOB10_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB10_RSA_KeyGen(b10rsa,1024);
        BN_print_fp(stdout,b10rsa->n);
        printf(" ");
        BN_print_fp(stdout,b10rsa->e);
        printf(" ");
        BN_print_fp(stdout,b10rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b10rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b10rsa->e, argv[2]);
            BOB10_RSA_Enc(out,in, b10rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b10rsa->d, argv[2]);
            BOB10_RSA_Dec(out,in, b10rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b10rsa!= NULL) BOB10_RSA_free(b10rsa);

    return 0;
}