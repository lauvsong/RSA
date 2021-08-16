#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

typedef struct _b10rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB10_RSA;

BOB10_RSA *BOB10_RSA_new();
int BOB10_RSA_free(BOB10_RSA *b10rsa);
int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits);
int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa);
int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa);

BOB10_RSA *BOB10_RSA_new(){
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


int BOB10_RSA_free(BOB10_RSA *b10rsa){
    OPENSSL_free(b10rsa->e);
    OPENSSL_free(b10rsa->d);
    OPENSSL_free(b10rsa->n);
    OPENSSL_free(b10rsa);
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