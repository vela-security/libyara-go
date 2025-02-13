#include <yara.h>
#include <yara/libyara_cgo.h>

#define YARA_OK   1
#define YARA_ERR  0 

#define YARA_CALLBACK_CONTINUE 0
#define YARA_CALLBACK_ABORT    1
#define YARA_CALLBACK_ERROR    2

// 扫描回调函数
static int yara_callback_exec(YR_SCAN_CONTEXT* context,
                    int code,
                    void* data,
                    void* userdata)
{
    if (userdata == NULL)
    {
      return CALLBACK_ERROR; 
    }
    
    yara_userdata_t* ud = (yara_userdata_t*) userdata;
    if (data == NULL)
    {
		CALL_E(ud->errlog, 0 ,"NOT FOUND SCAN RULE DATA");
        return CALLBACK_ABORT;
    }

    ud->offset++;

    if (ud->handle == NULL)
    {
		CALL_E(ud->errlog, 0 ,"NOT FOUND SCAN RULE HANDLE");
        return CALLBACK_ABORT;
    }


    YR_RULE* rule = (YR_RULE*) data;
    yara_rule_t rule_cgo = {
      .code = code, 
      .offset = ud->offset,
      .flags = rule->flags,
      .rule = YARA_STR(rule->identifier),
      .tags = YARA_STR(rule->tags),
    };
    return ud->handle(&rule_cgo);
}

static int yara_context_check_cgo(yara_context_cgo_t* ctx , yara_error_callback err) 
{
    if (ctx == NULL)
    {
        CALL_E(err,0, "yara context == null");
        return YARA_ERR;
    }

    if (ctx->compiler == NULL)
    {
        CALL_E(err, 0, "yara context.compiler == null");
        return YARA_ERR;
    }

    if (ctx->status != 200)
    {
        CALL_E(err, 0, "yara context.status != 200");
        return YARA_ERR;
    }

    return YARA_OK;
}

YR_API int yara_create_context_cgo(
    yara_context_cgo_t* ctx,
    yara_print_callback show,
    yara_error_callback err)
{
    int rc = yr_initialize();
    if (rc != ERROR_SUCCESS)
    {
      ctx->status = 500;
      CALL_E(err, rc, "initialize fail");
      return YARA_ERR;
    }

    rc = yr_compiler_create(&ctx->compiler);
    if (rc != ERROR_SUCCESS)
    {
      ctx->status = 500;
      CALL_E(err, rc, "create compiler fail");
      return YARA_ERR;
    }


    ctx->status = 200;
    CALL_P(show, "create rules succeed");
    return YARA_OK;
}


YR_API int yara_context_add_rule_buff_cgo(yara_context_cgo_t* ctx,  const char *rule, yara_error_callback err) 
{
    CALL_E(err, 0 ,"start add rule");

    int rc; 
    rc = yara_context_check_cgo(ctx, err);
    if (rc != 1)
    {
        return 0;
    }

    rc = yr_compiler_add_string(ctx->compiler, rule, NULL);
    if (rc != 0)
    {
        CALL_E(err, rc, "yara context add rule string fail"); 
        return 0;
    }

    ctx->rule_size++;
    return 1;
}

YR_API int yara_context_add_rule_file_cgo(yara_context_cgo_t* ctx,  char *path, const char *ns ,yara_error_callback err) 
{
    int   rc; 
    FILE* file;
    rc = yara_context_check_cgo(ctx, err);
    if (rc != 1)
    {
      return 0;
    }
    
    file = fopen(path, "r");
    if (file == NULL)
    {
        CALL_E(err, 0, "open file error");
        return 0;
    }
    

    rc = yr_compiler_add_file(ctx->compiler, file, ns, path);
    if (rc != 0)
    {
        fclose(file);
        CALL_E(err, rc, "yara context add rule string fail"); 
        return 0;
    }
    
    ctx->rule_size++;
    fclose(file);
    return 1;
}

YR_API int yara_context_apply_cgo(yara_context_cgo_t* ctx, yara_error_callback err)
{
    int rc;
    rc = yara_context_check_cgo(ctx, err);
    if (rc != 1)
    {
        return 0; 
    }

    rc = yr_compiler_get_rules(ctx->compiler, &ctx->rules);
    if (rc != ERROR_SUCCESS)
    {
        CALL_E(err, rc, "yara context get rules fail");
        return 0;
    }
    return 1;
}

//内容扫描
YR_API int yara_context_scan_mem_cgo( 
    yara_context_cgo_t *ctx,          //ctx 变量
    const char *buffer,               //扫描内容
    yara_scan_callback  handle,       //命中回调
    yara_error_callback errlog)       //报错回调
{
    int rc;
    yara_userdata_t userdata;

    userdata.handle = handle;
    userdata.errlog = errlog;
    userdata.offset = 0;

    rc = yara_context_check_cgo(ctx, errlog);
    if (rc != 1) {
        return YARA_ERR;
    }

    if (ctx->rules == NULL)
    {
        CALL_E(errlog, 0, "yara context.rules == null");
        return YARA_ERR;
    }
    
    rc = yr_rules_scan_mem( ctx->rules, (uint8_t *) buffer, strlen(buffer), 0, yara_callback_exec, &userdata, 0);
    if (rc != ERROR_SUCCESS)
    {
        CALL_E(errlog,rc, "yara rules scan mem fail");
        return YARA_ERR;
    }    
    return YARA_OK;
}

YR_API int yara_context_scan_file_cgo(
    yara_context_cgo_t* ctx,
    const char* path,
    uint32_t    flags,
    uint32_t    timeout,
    yara_scan_callback  handle,
    yara_error_callback errlog)
{
    int rc;
    yara_userdata_t userdata;

    userdata.handle = handle;
    userdata.errlog = errlog;
    userdata.offset = 0;

    rc = yara_context_check_cgo(ctx, errlog);
    if (rc != 1) {
        return YARA_ERR;
    }

    if (ctx->rules == NULL)
    {
        CALL_E(errlog, 0, "yara context.rules == null");
        return YARA_ERR;
    }

    rc = yr_rules_scan_file(ctx->rules, path, flags, yara_callback_exec, &userdata, timeout);
    if (rc != ERROR_SUCCESS)
    {
        CALL_E(errlog, rc, "yara scan file fail");
        return YARA_ERR;
    }

    return YARA_OK;
}

YR_API void yara_context_free_cgo(yara_context_cgo_t* ctx) {
    if (ctx == NULL)
    {
        return;
    }

    if (ctx->rules != NULL)
    {
        yr_rules_destroy(ctx->rules);
        ctx->rules = NULL;
    }

    if (ctx->compiler != NULL) {
        yr_compiler_destroy(ctx->compiler);
        ctx->compiler = NULL;
    }
}
