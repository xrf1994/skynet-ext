#include "skynet.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <assert.h>
#include <libgen.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

// 日志文件大小限制
#define LOG_MAX_SIZE 400*1024*1024
#define LOG_DATE_CHECK "500" //5秒检测一次日期

struct ex_loggersvr {
    FILE * f; // 写入文件
    FILE * c; // 控制台
    char lpath[100];
    char fpath[100];
    char datebuf[100];
    unsigned findex;
    unsigned int fwrites;
};

struct ex_loggersvr *
ex_loggersvr_create(void) {
    struct ex_loggersvr * inst = skynet_malloc(sizeof(*inst));
    memset(inst, 0, sizeof(*inst));
    return inst;
}

void
ex_loggersvr_release(struct ex_loggersvr * inst) {
    if (inst->f) {
        fflush(inst->f);
        fclose(inst->f);
    }
    skynet_free(inst);
}

void
update_log_path(struct ex_loggersvr * inst){
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(inst->datebuf, sizeof(inst->datebuf), "%Y%m%d", &tm);
    if (inst->findex > 0){
        snprintf(inst->fpath, sizeof(inst->fpath), "%s-%s_%d", inst->lpath, inst->datebuf, inst->findex);
    }else{
        snprintf(inst->fpath, sizeof(inst->fpath), "%s-%s", inst->lpath, inst->datebuf);
    }
}

void
refopen_log_file(struct ex_loggersvr * inst){
    if(inst->f){
        fflush(inst->f);
        fclose(inst->f);
    }
    inst->f = fopen(inst->fpath, "a+");
    if(!inst->f){
        int er = errno;
        fprintf(stderr, "refopen log file error: %d, path: %s \n", er, inst->fpath);
    }else{
        inst->fwrites = 0;
    }
}

static int
ex_loggersvr_cb(struct skynet_context * ctx, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz) {
    struct ex_loggersvr * inst = ud;
    switch (type) {
        case PTYPE_SYSTEM:
            update_log_path(inst);
            refopen_log_file(inst);
            break;
        case PTYPE_TEXT:{
            time_t now = time(NULL);
            struct tm tm;
            localtime_r(&now, &tm);
            char timebuf[64];
            strftime(timebuf, sizeof(timebuf), "%Y%m%d-%H:%M:%S", &tm);

            size_t len = fprintf(inst->f, "[:%08x][%s] ", source, timebuf);
            fwrite(msg, sz , 1, inst->f);
            fprintf(inst->f, "\n");
            fflush(inst->f);
            inst->fwrites += len + sz + 1;
            if(inst->fwrites >= LOG_MAX_SIZE){
                inst->findex ++;
                update_log_path(inst);
                refopen_log_file(inst);
            }

            if(inst->c){
                fprintf(inst->c, "[:%08x][%s] ", source, timebuf);
                fwrite(msg, sz , 1, inst->c);
                fprintf(inst->c, "\n");
                fflush(inst->c);
            }
            break;
        case PTYPE_RESPONSE:{
                time_t now = time(NULL);
                struct tm tm;
                localtime_r(&now, &tm);
                char datebuf[100];
                strftime(datebuf, sizeof(datebuf), "%Y%m%d", &tm);
                if(strcmp(datebuf, inst->datebuf) != 0){
                    update_log_path(inst);
                    refopen_log_file(inst);
                }
                skynet_command(ctx, "TIMEOUT", LOG_DATE_CHECK);
            }
            break;
        }
    }
    return 0;
}

int
ex_loggersvr_init(struct ex_loggersvr * inst, struct skynet_context *ctx, const char * path) {
    if (path){
        memcpy(inst->lpath, path, strlen(path) + 1);
        update_log_path(inst);
        refopen_log_file(inst);
        if(!inst->f)
            return 1;
    }
    if(!skynet_command(ctx, "GETENV", "daemon")){
        inst->c = stdout;
    }
    skynet_callback(ctx, inst, ex_loggersvr_cb);
    skynet_command(ctx, "REG", ".logger");
    skynet_command(ctx, "TIMEOUT", LOG_DATE_CHECK);
    return 0;
}

static lua_Integer g_level = 1;

static int
l_set_level(lua_State * L){
    g_level = luaL_checkinteger(L, 1);
    return 0;
}

static int
l_get_level(lua_State * L){
    lua_pushinteger(L, g_level);
    return 1;
}

static luaL_Reg REG[] = {
    { "set_level", l_set_level },
    { "get_level", l_get_level },
    { NULL, NULL },
};

int
luaopen_ex_loggersvr_c(lua_State * L){
    luaL_newlib(L, REG);
    return 1;
}
