#ifndef AES_AES_H
#define AES_AES_H

#include <stdint.h>

typedef void AESKey;
AESKey *allocate_key128();
void generate_key128(AESKey *k, const uint8_t *bytes);
void free_key128(AESKey *k);
void encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr);
void decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr);

#endif
