#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>

#include "mjs_core.h"
#include "mjs_exec.h"
#include "mjs_internal.h"
#include "mjs_primitive.h"
// #include "mjs_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct mjs *mjs = mjs_create();

    mjs_val_t res = MJS_UNDEFINED;
    mjs_err_t err = MJS_OK;

    err = mjs_exec(mjs, (const char *)data, &res);

    mjs_destroy(mjs);

    return EXIT_SUCCESS;
}