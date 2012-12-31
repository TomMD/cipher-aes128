#ifndef AES_TYPES_H
#define AES_TYPES_H

typedef struct {
    uint8_t nbr;
    uint8_t _padding[7];
    uint8_t data[16*14*2];
} aes_key;

#endif
