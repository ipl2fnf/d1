//============================================================================
// Name        : md5sig.cpp
// Author      : Ashish Tyagi
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int padding = RSA_PKCS1_PADDING;

void printLastError(char *msg)
{
    char * err = malloc(130);
    ;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

RSA * createRSA(unsigned char * key, int public)
{
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
    {
        printf("Failed to create key BIO");
        return 0;
    }
    if (public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL)
    {
        printf("Failed to create RSA");
    }

    return rsa;
}

int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

char* read_file(const char *file_name_, long* size_)
{
    FILE *fp;
    char *buffer;

    fp = fopen(file_name_, "rb");
    if (!fp)
        perror(file_name_), exit(1);

    fseek(fp, 0L, SEEK_END);
    *size_ = ftell(fp);
    rewind(fp);

    /* allocate memory for entire content */
    buffer = calloc(1, *size_ + 2);
    if (!buffer)
        fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the buffer */
    if (1 != fread(buffer, *size_, 1, fp))
        fclose(fp), free(buffer), fputs("entire read fails", stderr), exit(1);

    buffer[*size_] = '\0';
    fclose(fp);
    return buffer;

}

void usage(int argc, char ** argv)
{
    printf("%s orignal_data_file signed_hashed_message_file public_key_file\n", argv[0]);
}

int verify(const char *orignal_data_file_, char * signed_hashed_message_file_, char * public_key_file_)
{
    return 0;
}

int main(int argc, char ** argv)
{

    // use below extract hash from plain text
    //openssl md5 -c data.txt  > hash
    // use below cmd to sign hash
    //openssl rsautl -sign -in hash -inkey private.pem -out signed_hash
    // how to compile?
    //gcc -O0 -g3 -Wall -c  -o "src/md5sig.o" "../src/md5sig.c"
    //gcc  -o md5sig  md5sig.c -lcrypto
    // how to run?
    //./md5sig data.txt signed_hash public.pem

    if (argc < 4)
    {
        printf("invalid arguments\n");
        usage(argc, argv);
        exit(1);
    }

    int encrypted_length;
    int decrypted_length;
    long plainTextLen;
    char * plainText;
//    long privatekeyLen;
//    char * privatekey;
    long publicKeyLen;
    char * publicKey;
    long signed_hashed_message_len;
    char * signed_hashed_message;

    plainText = read_file(argv[1], &plainTextLen);
//    printf("plainTextLen = %d\n", plainTextLen);
//    printf("plainText = %s\n", plainText);
//    privatekey = read_file("/home/ashish/workspace/md5sig/private.pem", &privatekeyLen);
//    printf("privatekeyLen = %d\n", privatekeyLen);
//    printf("privatekey = %s\n", privatekey);
    signed_hashed_message = read_file(argv[2], &signed_hashed_message_len);
//    printf("signed_hashed_message_len = %d\n", signed_hashed_message);
//    printf("signed_hashed_message = %s\n", signed_hashed_message);
    publicKey = read_file(argv[3], &publicKeyLen);
//    printf("publicKeyLen = %d\n", publicKeyLen);
//    printf("publicKey = %s\n", publicKey);

//    unsigned char encrypted[4098] =
//               { };
       unsigned char decrypted[4098] =
               { };

//    int encrypted_length = public_encrypt(plainText, strlen(plainText), publicKey, encrypted);
//    if (encrypted_length == -1)
//    {
//        printLastError("Public Encrypt failed ");
//        exit(0);
//    }
//    printf("Encrypted length =%d\n", encrypted_length);
//
//    int decrypted_length = private_decrypt(encrypted, encrypted_length, privateKey, decrypted);
//    if (decrypted_length == -1)
//    {
//        printLastError("Private Decrypt failed ");
//        exit(0);
//    }
//    printf("Decrypted Text =%s\n", decrypted);
//    printf("Decrypted Length =%d\n", decrypted_length);

//    encrypted_length = private_encrypt(plainText, plainTextLen, privatekey, encrypted);
//    if (encrypted_length == -1)
//    {
//        printLastError("Private Encrypt failed");
//        exit(0);
//    }
//
//    printf("Encrypted length =%d\n", encrypted_length);

    decrypted_length = public_decrypt(signed_hashed_message, signed_hashed_message_len, publicKey, decrypted);
    if (decrypted_length == -1)
    {
        printLastError("Public Decrypt failed");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypted);
    printf("Decrypted Length =%d\n", decrypted_length);
    return 0;
}
