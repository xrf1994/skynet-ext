#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "lua.h"
#include "lauxlib.h"


#define AES_BLOCK_SZ 16

static inline void
xor_key(uint8_t * key, size_t size, uint32_t xor) {
    int i;
    for (i=0;i<size;i+=sizeof(uint32_t)) {
        uint32_t * k = (uint32_t *)&key[i];
        *k ^= xor;
    }
}

static int laes_encode(lua_State * L){
    size_t data_len, key_len;
    const char * data = luaL_checklstring(L, 1, &data_len);
    const char * key = luaL_checklstring(L, 2, &key_len);
    if(data_len == 0 || (key_len != 16 && key_len != 24 && key_len != 32)){
        return luaL_error(L, "params error");
    }
    size_t tsz = data_len;
    size_t bsz = 0;
    if(0 != (tsz % AES_BLOCK_SZ)){
        tsz = data_len + (AES_BLOCK_SZ - (data_len % AES_BLOCK_SZ));
        bsz = tsz - data_len;
    }else{
        tsz = data_len + AES_BLOCK_SZ;
        bsz = AES_BLOCK_SZ;
    }
    unsigned char * buf = malloc(tsz);
    memset(buf, bsz, tsz);
    memcpy(buf, data, data_len);
    unsigned char * out = malloc(tsz);
    memset(out, 0, tsz);

    AES_KEY aes_key;
    int ret = AES_set_encrypt_key(key, key_len * 8, &aes_key);
    for(size_t i = 0; i < tsz / AES_BLOCK_SZ; i ++){
        AES_ecb_encrypt(buf + i * AES_BLOCK_SZ, out + i * AES_BLOCK_SZ, &aes_key, AES_ENCRYPT);
        // AES_encrypt(buf + i * AES_BLOCK_SZ, out + i * AES_BLOCK_SZ, &aes_key);
    }
    lua_pushlstring(L, out, tsz);
    free(buf);
    free(out);
    return 1;
}

static int laes_decode(lua_State * L){
    size_t data_len, key_len;
    const char * data = luaL_checklstring(L, 1, &data_len);
    const char * key = luaL_checklstring(L, 2, &key_len);
    if(data_len == 0 || (key_len != 16 && key_len != 24 && key_len != 32)){
        return luaL_error(L, "params error");
    }
    size_t tsz = data_len;
    if(0 != (tsz % AES_BLOCK_SZ)){
        tsz = data_len + (AES_BLOCK_SZ - (data_len % AES_BLOCK_SZ));
    }
    unsigned char * buf = malloc(tsz);
    memset(buf, 0, tsz);
    memcpy(buf, data, data_len);
    unsigned char * out = malloc(tsz);
    memset(out, 0, tsz);

    AES_KEY aes_key;
    int ret = AES_set_decrypt_key(key, key_len * 8, &aes_key);
    for(size_t i = 0; i < tsz / AES_BLOCK_SZ; i ++){
        AES_ecb_encrypt(buf + i * AES_BLOCK_SZ, out + i * AES_BLOCK_SZ, &aes_key, AES_DECRYPT);
        // AES_decrypt(buf + i * AES_BLOCK_SZ, out + i * AES_BLOCK_SZ, &aes_key);
    }
    lua_pushlstring(L, out, tsz);
    free(buf);
    free(out);
    return 1;
}

static int lhmac_sha256(lua_State * L){
    size_t key_sz = 0;
    const uint8_t * key = (const uint8_t *)luaL_checklstring(L, 1, &key_sz);
    size_t text_sz = 0;
    const uint8_t * text = (const uint8_t *)luaL_checklstring(L, 2, &text_sz);
    SHA256_CTX ctx1, ctx2;
    uint8_t digest1[SHA256_DIGEST_LENGTH];
    uint8_t digest2[SHA256_DIGEST_LENGTH];
    uint8_t rkey[SHA256_CBLOCK];
    memset(rkey, 0, SHA256_CBLOCK);

    if (key_sz > SHA256_CBLOCK) {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, key, key_sz);
        SHA256_Final(rkey, &ctx);
        key_sz = SHA256_DIGEST_LENGTH;
    } else {
        memcpy(rkey, key, key_sz);
    }

    xor_key(rkey, SHA256_CBLOCK, 0x5c5c5c5c);
    SHA256_Init(&ctx1);
    SHA256_Update(&ctx1, rkey, SHA256_CBLOCK);

    xor_key(rkey, SHA256_CBLOCK, 0x5c5c5c5c ^ 0x36363636);
    SHA256_Init(&ctx2);
    SHA256_Update(&ctx2, rkey, SHA256_CBLOCK);
    SHA256_Update(&ctx2, text, text_sz);
    SHA256_Final(digest2, &ctx2);

    SHA256_Update(&ctx1, digest2, SHA256_DIGEST_LENGTH);
    SHA256_Final(digest1, &ctx1);

    lua_pushlstring(L, (const char *)digest1, SHA256_DIGEST_LENGTH);
    return 1;
}

static int lsha256(lua_State * L){
    size_t size = 0;
    const char * data = luaL_checklstring(L, 1, &size);
    SHA256_CTX ctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final(digest, &ctx);
    lua_pushlstring(L, digest, SHA256_DIGEST_LENGTH);
    return 1;
}

static int lrsa_sign(lua_State * L){
    size_t pem_size = 0;
    const char * pem = luaL_checklstring(L, 1, &pem_size);
    size_t data_size = 0;
    const char * data = luaL_checklstring(L, 2, &data_size);
    BIO *bufio = NULL;
    RSA *rsa = NULL;
    bufio = BIO_new_mem_buf((void*)pem, pem_size);
    rsa = PEM_read_bio_RSAPrivateKey(bufio, NULL, NULL, NULL);
    if(!rsa) {
        return luaL_error(L, "error pem");
    }
    uint8_t * out = malloc(RSA_size(rsa));
    unsigned int out_size = 0;
    int ret = RSA_sign(NID_sha256, data,  data_size, out, &out_size, rsa);
    if(ret != 1){
        free(out);
        return luaL_error(L, "rsa sign error:%d",  ret);
    }
    lua_pushlstring(L, out, out_size);
    free(out);
    return 1;
}

static int laes_gcm_decode(lua_State * L){
    size_t data_len;
    const char * data = luaL_checklstring(L, 1, &data_len);
    size_t key_len;
    const char * key = luaL_checklstring(L, 2, &key_len);
    size_t aad_len;
    const char * aad = luaL_checklstring(L, 3, &aad_len);
    size_t iv_len;
    const char * iv = luaL_checklstring(L, 4, &iv_len);

    printf("data_len:%d\n", data_len);
    if(data_len > 16){
        data_len = data_len - 16;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    int outlen;
    // EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len);
    unsigned char * outbuf = malloc(data_len);
    EVP_DecryptUpdate(ctx, outbuf, &outlen, data, data_len);
    // Set expected tag value
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag);
    int final_len;
    EVP_CIPHER_CTX_free(ctx);
    lua_pushlstring(L, outbuf, outlen);
    free(outbuf);
    return 1;

}

int luaopen_lopenssl_c(lua_State *L) {
    luaL_checkversion(L);

    luaL_Reg l[] = {
        {"aes_encode", laes_encode},
        {"aes_decode", laes_decode},
        {"hmac_sha256", lhmac_sha256},
        {"sha256", lsha256 },
        {"rsa_sign", lrsa_sign },
        {"aes_gcm_decode", laes_gcm_decode},

        {NULL, NULL}
    };
    luaL_newlib(L, l);
    return 1;
}

