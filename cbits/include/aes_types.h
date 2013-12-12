#ifndef AES_TYPES_H
#define AES_TYPES_H
#include <stdint.h>
#include "block128.h"

typedef block128 aes_block;

typedef struct {
    uint8_t nbr;
    uint8_t _padding[7];
    uint8_t data[16*14*2];
} aes_key;

/* size = 4*16+2*8+aes_key=456 = 536 */
typedef struct {
    aes_block h;        // init
    aes_key key;
} aes_gcm;

typedef struct {
    aes_block iv;
    aes_block civ;
    aes_block tag;      // finish, aad, encrypt,decrypt
    uint64_t length_input;
    uint64_t length_aad;
} aes_gcm_ctx;

#endif
