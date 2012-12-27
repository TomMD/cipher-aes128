#include "aes/gladman/aes.h"
#include "aes/aes.h"
#include <string.h>

/* The "HAVE_NI" macro is also defined (or not) but we no longer need that
 * since we're doing a runtime detection... again. */
#if (defined(__i386__) || defined(__x86_64__)) && defined(HAVE_AES_INTRINSICS) && !defined(AVOID_NI)
#define TRY_NI
#include "aes/ni/aes_x86ni.h"
#endif

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

typedef struct {
    aes_encrypt_ctx enc;
    aes_decrypt_ctx dec;
} encDecKey;

#ifdef TRY_NI
AESKey *detect_and_allocate_key128();
AESKey *(*allocate_key128_ptr)(void) = &detect_and_allocate_key128;

AESKey *allocate_key128()
{
        return (*allocate_key128_ptr)();
}

AESKey *allocate_key128_ni()
{
        void *k=NULL;
        k = (void *)malloc(sizeof(aes_key));
        return k;
}

AESKey *allocate_key128_gladman()
{
        void *k=NULL;
        k = (void *)malloc(sizeof(encDecKey));
        return k;
}

AESKey *detect_and_allocate_key128()
{
        if(cpu_has_ni())
                allocate_key128_ptr = &allocate_key128_ni;
        else allocate_key128_ptr = &allocate_key128_gladman;
        return (*allocate_key128_ptr)();
}

#else
AESKey *allocate_key128()
{
        void *k=NULL;
        k = (void *)malloc(sizeof(encDecKey));
        return k;
}
#endif

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

void generate_key128_gladman(AESKey *k, const uint8_t *bytes)
{
    encDecKey *key = (encDecKey *)k;
    aes_encrypt_key128((const unsigned char *)bytes
                      ,&key->enc);
    aes_decrypt_key128((const unsigned char *)bytes
                      ,&key->dec);
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
                generate_key128_ptr = &generate_key128_gladman;
        }
        (*generate_key128_ptr)(k,bytes);
}

#else
void generate_key128(AESKey *k, const uint8_t *bytes)
{
    encDecKey *key = (encDecKey *)k;
    aes_encrypt_key128((const unsigned char *)bytes
                      ,&key->enc);
    aes_decrypt_key128((const unsigned char *)bytes
                      ,&key->dec);
}
#endif

#ifdef TRY_NI
void detect_and_free_key128(AESKey *k);
void (*free_key128_ptr)(AESKey *) = &detect_and_free_key128;

void free_key128(AESKey *k)
{
        (*free_key128_ptr)(k);
}

void free_key128_ni(AESKey *k)
{
        memset(k, 0, sizeof(aes_key));
        free(k);
}

void free_key128_gladman(AESKey * k)
{
        memset(k, 0, sizeof(encDecKey));
        free(k);
}

void detect_and_free_key128(AESKey *k)
{
        if(cpu_has_ni()) free_key128_ptr = &free_key128_ni;
        else free_key128_ptr = &free_key128_gladman;
        (*free_key128_ptr)(k);
}
#else
void free_key128(AESKey *k)
{
        memset(k, 0, sizeof(aes_encrypt_ctx));
        free(k);
}
#endif

#ifdef TRY_NI
void detect_and_encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr);
void (*encrypt_ecb_ptr)(const AESKey *, uint8_t *, const uint8_t *, const uint32_t) = &detect_and_encrypt_ecb;

void encrypt_ecb_ni(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        aes_ni_encrypt_ecb(dst, (aes_key *)k, src, nr);
}

void encrypt_ecb_gladman(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        encDecKey *key=(encDecKey *)k;
        aes_ecb_encrypt((const unsigned char*)src
                       ,(unsigned char*)dst
                       ,(int)nr * 16, &key->enc);
}

void encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        (*encrypt_ecb_ptr)(k,dst,src,nr);
}

void detect_and_encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        if(cpu_has_ni()) encrypt_ecb_ptr = &encrypt_ecb_ni;
        else encrypt_ecb_ptr = &encrypt_ecb_gladman;
        (*encrypt_ecb_ptr)(k,dst,src,nr);
}
#else
void encrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        encDecKey *key=(encDecKey *)k;
        aes_ecb_encrypt((const unsigned char*)src
                       ,(unsigned char*)dst
                       ,(int)nr * 16, key->enc);
}
#endif

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

void decrypt_ecb_gladman(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        encDecKey *key = (encDecKey *)k;
        aes_ecb_decrypt((const unsigned char*)src
                       ,(unsigned char*)dst
                       ,(int)nr * 16, &key->dec);
}

void detect_and_decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        if(cpu_has_ni()) decrypt_ecb_ptr = &decrypt_ecb_ni;
        else decrypt_ecb_ptr = &decrypt_ecb_gladman;
        (*decrypt_ecb_ptr)(k,dst,src,ni);
}
#else
void decrypt_ecb(const AESKey *k, uint8_t *dst, const uint8_t *src, const uint32_t nr)
{
        encDecKey *key = (encDecKey *)k;
        aes_ecb_decrypt((const unsigned char*)src
                       ,(unsigned char*)dst
                       ,(int)nr * 16, &key->dec);
}
#endif
