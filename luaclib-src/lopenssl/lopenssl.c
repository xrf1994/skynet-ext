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

static int lrsa_verify(lua_State * L){
    size_t pem_size = 0;
    const char * pem = luaL_checklstring(L, 1, &pem_size);
    size_t data_size = 0;
    const char * data = luaL_checklstring(L, 2, &data_size);
    size_t sign_size = 0;
    const char * sign = luaL_checklstring(L, 3, &sign_size);
    if(pem_size < 128){
        return luaL_error(L, "error pem");
    }

    static const char * pkcs1_header = "-----BEGIN RSA PUBLIC KEY-----";
	static const char * pkcs8_header = "-----BEGIN PUBLIC KEY-----";
    BIO *bio = NULL;
    RSA *rsa = NULL;
    bio = BIO_new_mem_buf((void*)pem, pem_size);
    if(strncmp(pem, pkcs1_header, 30) == 0){
		rsa = PEM_read_bio_RSAPublicKey(bio,NULL,NULL,NULL);
	}
	else if(strncmp(pem, pkcs8_header, 26) == 0){
		rsa = PEM_read_bio_RSA_PUBKEY(bio,NULL,NULL,NULL);
	}
    if(!rsa) {
        return luaL_error(L, "error pem");
    }
    int ret = RSA_verify(NID_sha256, data, data_size, sign, &sign_size, rsa);
    lua_pushboolean(L, ret);
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

    // if(data_len > 16){
    //     data_len = data_len - 16;
    // }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

    int out_len;
    EVP_DecryptUpdate(ctx, NULL, &out_len, aad, aad_len);
    unsigned char * outbuf = malloc(data_len);
    EVP_DecryptUpdate(ctx, outbuf, &out_len, data, data_len);
    if(out_len > 16){ //remove 16b tag
        out_len = out_len - 16;
    }
    // Set expected tag value
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag);
    // int rc = EVP_CipherFinal_ex(ctx, outbuf+out_len, &out_len);
    // printf("rc: %d %d  %d\n", rc, data_len, out_len);
    EVP_CIPHER_CTX_free(ctx);
    lua_pushlstring(L, outbuf, out_len);
    free(outbuf);
    return 1;

}

static int laes_gcm_decode2(lua_State * L){
    size_t data_len;
    const char * data = luaL_checklstring(L, 1, &data_len);
    size_t key_len;
    const char * key = luaL_checklstring(L, 2, &key_len);
    size_t iv_len;
    const char * iv = luaL_checklstring(L, 3, &iv_len);
    size_t tag_len;
    const char * tag = luaL_checklstring(L, 4, &tag_len);
    size_t aad_len;
    const char * aad = luaL_checklstring(L, 5, &aad_len);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    // EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    int out_len;
    // if(aad_len){
        EVP_DecryptUpdate(ctx, NULL, &out_len, aad, aad_len);
    // }
    unsigned char * outbuf = malloc(data_len);
    EVP_DecryptUpdate(ctx, outbuf, &out_len, data, data_len);

    if(tag_len){
        // Set expected tag value
        int tag_out_len;
        unsigned char * tagbuf = malloc(data_len);
        memcpy(tagbuf, outbuf, out_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag);
        int rc = EVP_CipherFinal_ex(ctx, tagbuf, &tag_out_len);
        free(tagbuf);
        if(!rc){
            EVP_CIPHER_CTX_free(ctx);
            free(outbuf);
            return luaL_error(L, "faild verify tag");
        }
    }else{
        if(out_len > 16){ //remove 16b tag
           out_len = out_len - 16;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    lua_pushlstring(L, outbuf, out_len);
    free(outbuf);
    return 1;
}

static int lhash(lua_State * L){
    size_t size;
    const char * dat = luaL_checklstring(L, 1, &size);

    uint32_t hash = 1315423911;
    for(size_t i = 0; i < size; i++)
        hash ^= ((hash << 5) + dat[i] + (hash >> 2));
    lua_pushinteger(L, hash);
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
        {"rsa_verify", lrsa_verify },
        {"aes_gcm_decode", laes_gcm_decode},
        {"aes_gcm_decode2", laes_gcm_decode2},
        {"hash", lhash},

        {NULL, NULL}
    };
    luaL_newlib(L, l);
    return 1;
}

