//
// Created by vela on 2025/2/11.
//

#ifndef LIBYARA_GO_LIBYARA_CGO_H
#define LIBYARA_GO_LIBYARA_CGO_H

#include <yara.h>

#define cgo_ptr_t             uintptr_t
#define cast(any)             (cgo_ptr_t)any
#define YARA_STR(a)           (yara_str_t){.data=(char *)a , .size=strlen(a)}
#define YARA_STR_NULL()       (yara_str_t){.data=NULL , .size=0}
#define CALL_E(fn ,code, err) fn(code , &YARA_STR(err))
#define CALL_P(fn, b)         fn(&YARA_STR(b))


typedef struct yara_userdata_s    yara_userdata_t;
typedef struct yara_context_cgo_s yara_context_cgo_t;
typedef struct yara_str_s         yara_str_t;
typedef struct yara_rule_cgo_s    yara_rule_t;
typedef void (*yara_print_callback)(yara_str_t*);
typedef void (*yara_error_callback)(int , yara_str_t*);
typedef int  (*yara_scan_callback)(yara_rule_t *);

struct yara_str_s {
   uint32_t size;
   char    *data;
};

struct yara_rule_cgo_s
{
   uint32_t   code;
   uint32_t   offset;
   uint32_t   flags;
   yara_str_t rule;
   yara_str_t tags;
};

struct yara_userdata_s {
    int                 offset;
    yara_scan_callback  handle;
    yara_error_callback errlog;
};

struct yara_context_cgo_s {
    uint32_t      status;
    uint32_t      rule_size;
    uint32_t      total;
    uint32_t      succees;
    uint32_t      failed;
    uint32_t      debug;
    YR_COMPILER   *compiler;
    YR_RULES      *rules;
};

#endif //LIBYARA_GO_LIBYARA_CGO_H
