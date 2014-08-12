/*
 * This file has the code to solve exersise 3.8 and 3.9 in the crypto engineering
 * book. Exercise 3.8 gives you a key and a plaintext that you needs to encrypt,
 * exercise 3.9 gives you a ciphertext that you need to decrypt. Both exercises
 * share the same key.
 */

#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


unsigned char key[] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

unsigned char plaintext[] = {
    0x53, 0x9b, 0x33, 0x3b, 0x39, 0x70, 0x6d, 0x14, 0x90, 0x28, 0xcf, 0xe1, 0xd9, 0xd4, 0xa4, 0x07
};

unsigned char exercise_ciphertext[] = {
    0x29, 0x6c, 0x93, 0xfd, 0xf4, 0x99, 0xaa, 0xeb, 0x41, 0x94, 0xba, 0xbc, 0x2e, 0x63, 0x56, 0x1d
};



void print_text(unsigned char *text, int length) {
    int i;

    for (i = 0; i < length; i++) {

        if (i % 16 == 0) {
            printf("\n");
        }

        if (text[i] == 0) {
            printf("0x00 ");
        }

        else {
            printf("0x%hhX ", text[i]);
        }

    }

    printf("\n");
}


void encrypt(unsigned char *plaintext, unsigned char *key, int size, unsigned char *ciphertext) {
    int outlen, tmp_len, ret_val;

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_256_ecb(), NULL, key, NULL);

    ret_val = EVP_EncryptUpdate (&ctx, ciphertext, &outlen, plaintext, size);
    if (ret_val == 0) {
        printf("EVP_EncryptUpdate failed.\n");
        return;
    }

    ret_val = EVP_EncryptFinal_ex(&ctx, ciphertext + outlen, &tmp_len);
    if (ret_val == 0) {
        printf("EVP_EncryptFinal failed.\n");
    }

    outlen += tmp_len;

    EVP_CIPHER_CTX_cleanup(&ctx);
}


void decrypt(unsigned char *ciphertext, unsigned char *key, int size, unsigned char *plaintext) {
    int outlen, tmp_len, ret_val = 0;

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex (&ctx, EVP_aes_256_ecb(), NULL, key, NULL);

    ret_val = EVP_DecryptUpdate (&ctx, plaintext, &outlen, ciphertext, size);
    if (ret_val == 0) {
        printf("EVP_DecryptUpdate failed.\n");
        return;
    }


    ret_val = EVP_DecryptFinal_ex(&ctx, plaintext + outlen, &tmp_len);
    if (ret_val == 0) {
        printf("EVP_DecryptFinal failed.\n");
        return;
    }

    outlen += tmp_len;

    EVP_CIPHER_CTX_cleanup(&ctx);
}


int main() {

    unsigned char * enc_out = (unsigned char *) calloc(32, sizeof(sizeof(char)));
    unsigned char * dec_out = (unsigned char *) calloc(32, sizeof(sizeof(char)));

    printf("Exercise 3.8 plaintext:\n");
    print_text(plaintext, 16);

    printf("\n\nExercise 3.9 ciphertext:\n");
    print_text(exercise_ciphertext, 16);

    printf("\nEncrypting exercise 3.8 plaintext, ciphertext:\n");
    encrypt(plaintext, key, 16, enc_out);
    print_text(enc_out, 32);

    printf("\nDecrypting exercise 3.8 ciphertext:\n");
    decrypt(enc_out, key, 32, dec_out);
    print_text(dec_out, 16);

    // Decrypt Final will fail since there is only one block, but the results
    // Produced are correct anyways.
    printf("\nDecrypting exercise 3.9 ciphertext:\n");
    decrypt(exercise_ciphertext, key, 16, dec_out);
    print_text(dec_out, 16);

    printf("\nEncrypting exercise 3.9 plaintext:\n");
    encrypt(dec_out, key, 16, enc_out);
    print_text(enc_out, 16);

    return 0;
}
