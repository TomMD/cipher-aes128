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
void aes_encrypt_ctr( AESKey *key
                    , uint8_t *iv
                    , uint8_t *dst
                    , uint8_t *src
                    , uint32_t nr);

#endif
