#ifndef AES_AES_H
#define AES_AES_H

#include <stdint.h>
#include "aes_types.h"

typedef aes_key AESKey;
AESKey *allocate_key128();
void generate_key128(AESKey *k, const uint8_t *bytes);
void free_key128(AESKey *k);
void encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr);
void decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr);
void aes_gcm_full_encrypt( const AESKey *k
                         , uint8_t *iv, uint32_t ivLen
                         , uint8_t *aad, uint32_t aadLen
                         , uint8_t *pt, uint32_t ptLen
                         , uint8_t *ct, uint8_t *tag);
void aes_gcm_full_decrypt( const AESKey *k
                         , uint8_t *iv, uint32_t ivLen
                         , uint8_t *aad, uint32_t aadLen
                         , uint8_t *ct, uint32_t ctLen
                         , uint8_t *pt, uint8_t *tag);
void encrypt_ctr( const AESKey *key
                , const uint8_t *iv  /* 16 bytes buffer with the count */
                , uint8_t *newIV     /* the return buffer for the next IV (or NULL) */
                , uint8_t *dst       /* 'len' byte buffer for output */
                , const uint8_t *src /* 'len' bytes of input */
                , uint32_t len);     /* Length in bytes */

#endif
