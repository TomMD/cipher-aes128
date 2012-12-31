#include "aes_generic.h"
#include "aes.h"
#include <string.h>

/* The "HAVE_NI" macro is also defined (or not) but we no longer need that
 * since we're doing a runtime detection... again. */
#if (defined(__i386__) || defined(__x86_64__)) && defined(HAVE_AES_INTRINSICS) && !defined(AVOID_NI)
#define TRY_NI
#include "aes_x86ni.h"
#endif
#include "bitfn.h"
void gf_mul(block128 *a, block128 *b);

#ifdef TRY_NI
/**
 * Returns zero if false, non-zero otherwise
 */
int cpu_has_ni()
{
       uint32_t ax,bx,cx,dx,func=1;

       __asm__ volatile ("cpuid":\
           "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));
       return (cx & 0x2000000);
}
#endif

/* Allocation */
AESKey *allocate_key128()
{
        void *k=NULL;
        k = (void *)malloc(sizeof(aes_key));
        return k;
}

/* Generate Key */
#ifdef TRY_NI
void detect_and_generate_key128(AESKey *k, const uint8_t *bytes);
void (*generate_key128_ptr)(AESKey *,const uint8_t *) = &detect_and_generate_key128;

/**
 * Expand a 128 bit AES key.
 */
void generate_key128(AESKey *k, const uint8_t *bytes)
{
    (*generate_key128_ptr)(k,bytes);
}

void generate_key128_generic(AESKey *k, const uint8_t *bytes)
{
    aes_generic_init(k, bytes, 16);
}

void generate_key128_ni(AESKey *k, const uint8_t *bytes)
{
    aes_ni_init((aes_key *)k, bytes, 16);
}

void detect_and_generate_key128(AESKey *k, const uint8_t *bytes)
{
    if(cpu_has_ni()) {
            generate_key128_ptr = &generate_key128_ni;
    } else {
            generate_key128_ptr = &generate_key128_generic;
    }
    (*generate_key128_ptr)(k,bytes);
}

#else
void generate_key128(AESKey *k, const uint8_t *bytes)
{
    aes_generic_init(k, bytes, 16);
}
#endif

void free_key128(AESKey *k)
{
        memset(k, 0, sizeof(AESKey));
        free(k);
}

/* ECB Encrypt */
#ifdef TRY_NI
void detect_and_encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr);
void (*encrypt_ecb_ptr)(const AESKey *, uint8_t *, const uint8_t *, const uint32_t) = &detect_and_encrypt_ecb;

void encrypt_ecb_ni(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        aes_ni_encrypt_ecb(dst, (aes_key *)k, src, nr);
}

void encrypt_ecb_generic(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
    int i;
    for(i = 0; i<nr*16; i+=16) {
        aes_generic_encrypt_block
                       ( (aes_block*) dst+i
                       , k
                       , (const aes_block*)src+i);
    }
}

void encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        (*encrypt_ecb_ptr)(k,dst,src,nr);
}

void detect_and_encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        if(cpu_has_ni()) encrypt_ecb_ptr = &encrypt_ecb_ni;
        else encrypt_ecb_ptr = &encrypt_ecb_generic;
        (*encrypt_ecb_ptr)(k,dst,src,nr);
}
#else
void encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
    int i;
    for(i = 0; i<nr*16; i+=16) {
        aes_generic_encrypt_block
                       ( (aes_block*) dst+i
                       , k
                       , (const aes_block*)src+i);
    }
}
#endif

/* ECB Decrypt */
#ifndef TRY_NI
void detect_and_decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr);
void (*decrypt_ecb_ptr)(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr) = &detect_and_decrypt_ecb;

void decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        (*decrypt_ecb_ptr)(k,dst,src,nr);
}

void decrypt_ecb_ni(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        aes_ni_decrypt_ecb(dst, (aes_key *)k, src, nr);
}

void decrypt_ecb_generic(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
    int i;
    for(i = 0; i<nr*16; i+=16) {
        aes_generic_decrypt_block ( (aes_block*) dst+i
                                  , k
                                  , (const aes_block*)src+i);
    }
}

void detect_and_decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        if(cpu_has_ni()) decrypt_ecb_ptr = &decrypt_ecb_ni;
        else decrypt_ecb_ptr = &decrypt_ecb_generic;
        (*decrypt_ecb_ptr)(k,dst,src,ni);
}
#else
void decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
    int i;
    for(i = 0; i<nr*16; i+=16) {
        aes_generic_decrypt_block ( (aes_block*) dst+i
                                  , k
                                  , (const aes_block*)src+i);
    }
}
#endif


/* GCM */
static void gcm_ghash_add(aes_gcm *gcm, block128 *b)
{
        block128_xor(&gcm->tag, b);
        gf_mul(&gcm->tag, &gcm->h);
}

void aes_gcm_init(aes_gcm *gcm, const aes_key *key, uint8_t *iv, uint32_t len)
{
        gcm->length_aad = 0;
        gcm->length_input = 0;

        block128_zero(&gcm->h);
        block128_zero(&gcm->tag);
        block128_zero(&gcm->iv);

        memcpy(&gcm->key, key, sizeof(aes_key));

        /* prepare H : encrypt_K(0^128) */
        encrypt_ecb(key, (uint8_t *)&gcm->h, (const uint8_t *)&gcm->h, 1);

        if (len == 12) {
                block128_copy_bytes(&gcm->iv, iv, 12);
                gcm->iv.b[15] = 0x01;
        } else {
                uint32_t origlen = len << 3;
                int i;
                for (; len >= 16; len -= 16, iv += 16) {
                        block128_xor(&gcm->iv, (block128 *) iv);
                        gf_mul(&gcm->iv, &gcm->h);
                }
                if (len > 0) {
                        block128_xor_bytes(&gcm->iv, iv, len);
                        gf_mul(&gcm->iv, &gcm->h);
                }
                for (i = 15; origlen; --i, origlen >>= 8)
                        gcm->iv.b[i] ^= (uint8_t) origlen;
                gf_mul(&gcm->iv, &gcm->h);
        }

        block128_copy(&gcm->civ, &gcm->iv);
}

void aes_gcm_aad(aes_gcm *gcm, uint8_t *input, uint32_t length)
{
        gcm->length_aad += length;
        for (; length >= 16; input += 16, length -= 16) {
                gcm_ghash_add(gcm, (block128 *) input);
        }
        if (length > 0) {
                aes_block tmp;
                block128_zero(&tmp);
                block128_copy_bytes(&tmp, input, length);
                gcm_ghash_add(gcm, &tmp);
        }

}

void aes_gcm_encrypt(uint8_t *output, aes_gcm *gcm, uint8_t *input, uint32_t length)
{
        aes_block out;

        gcm->length_input += length;
        for (; length >= 16; input += 16, output += 16, length -= 16) {
                block128_inc_be(&gcm->civ);

                encrypt_ecb(&gcm->key, (uint8_t *)&out, (const uint8_t *)&gcm->civ, 1);
                block128_xor(&out, (block128 *) input);
                gcm_ghash_add(gcm, &out);
                block128_copy((block128 *) output, &out);
        }
        if (length > 0) {
                aes_block tmp;
                int i;

                block128_inc_be(&gcm->civ);
                /* create e(civ) in out */
                encrypt_ecb(&gcm->key, (uint8_t *)&out, (const uint8_t *)&gcm->civ, 1);
                /* initialize a tmp as input and xor it to e(civ) */
                block128_zero(&tmp);
                block128_copy_bytes(&tmp, input, length);
                block128_xor_bytes(&tmp, out.b, length); 

                gcm_ghash_add(gcm, &tmp);

                for (i = 0; i < length; i++) {
                        output[i] = tmp.b[i];
                }
        }
}

void aes_gcm_decrypt(uint8_t *output, aes_gcm *gcm, uint8_t *input, uint32_t length)
{
        aes_block out;

        gcm->length_input += length;
        for (; length >= 16; input += 16, output += 16, length -= 16) {
                block128_inc_be(&gcm->civ);

                encrypt_ecb(&gcm->key, (uint8_t *)&out, (const uint8_t *)&gcm->civ, 1);
                gcm_ghash_add(gcm, (block128 *) input);
                block128_xor(&out, (block128 *) input);
                block128_copy((block128 *) output, &out);
        }
        if (length > 0) {
                aes_block tmp;
                int i;

                block128_inc_be(&gcm->civ);

                block128_zero(&tmp);
                block128_copy_bytes(&tmp, input, length);
                gcm_ghash_add(gcm, &tmp);

                encrypt_ecb(&gcm->key, (uint8_t *)&out, (const uint8_t *)&gcm->civ, 1);
                block128_xor_bytes(&tmp, out.b, length); 

                for (i = 0; i < length; i++) {
                        output[i] = tmp.b[i];
                }
        }
}

void aes_gcm_finish(uint8_t *tag, aes_gcm *gcm)
{
        aes_block lblock;
        int i;

        /* tag = (tag-1 xor (lenbits(a) | lenbits(c)) ) . H */
        lblock.q[0] = cpu_to_be64(gcm->length_aad << 3);
        lblock.q[1] = cpu_to_be64(gcm->length_input << 3);
        gcm_ghash_add(gcm, &lblock);

        encrypt_ecb(&gcm->key, (uint8_t *)&lblock, (const uint8_t*)&gcm->iv, 1);
        block128_xor(&gcm->tag, &lblock);

        for (i = 0; i < 16; i++) {
                tag[i] = gcm->tag.b[i];
        }
}

void aes_gcm_full_encrypt( const AESKey *k
                         , uint8_t *iv, uint32_t ivLen
                         , uint8_t *aad, uint32_t aadLen
                         , uint8_t *pt, uint32_t ptLen
                         , uint8_t *ct, uint8_t *tag)
{
    aes_gcm gcm;
    aes_gcm_init(&gcm, k, iv, ivLen);
    aes_gcm_aad(&gcm, aad, aadLen);
    aes_gcm_encrypt(ct, &gcm,  pt, ptLen);
    aes_gcm_finish(tag, &gcm);
}

void aes_gcm_full_decrypt( const AESKey *k
                         , uint8_t *iv, uint32_t ivLen
                         , uint8_t *aad, uint32_t aadLen
                         , uint8_t *ct, uint32_t ctLen
                         , uint8_t *pt, uint8_t *tag)
{
    aes_gcm gcm;
    aes_gcm_init(&gcm, k, iv, ivLen);
    aes_gcm_aad(&gcm, aad, aadLen);
    aes_gcm_decrypt(pt, &gcm,  ct, ctLen);
    aes_gcm_finish(tag, &gcm);
}


/* this is a really inefficient way to GF multiply.
 * the alternative without hw accel is building small tables
 * to speed up the multiplication.
 * TODO: optimise with tables
 */
void gf_mul(block128 *a, block128 *b)
{
        uint64_t a0, a1, v0, v1;
        int i, j;

        a0 = a1 = 0;
        v0 = cpu_to_be64(a->q[0]);
        v1 = cpu_to_be64(a->q[1]);

        for (i = 0; i < 16; i++)
                for (j = 0x80; j != 0; j >>= 1) {
                        uint8_t x = b->b[i] & j;
                        a0 ^= x ? v0 : 0;
                        a1 ^= x ? v1 : 0;
                        x = (uint8_t) v1 & 1;
                        v1 = (v1 >> 1) | (v0 << 63);
                        v0 = (v0 >> 1) ^ (x ? (0xe1ULL << 56) : 0);
                }
        a->q[0] = cpu_to_be64(a0);
        a->q[1] = cpu_to_be64(a1);
}
