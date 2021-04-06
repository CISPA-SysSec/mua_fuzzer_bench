//
// Created by Björn Mathis on 07.11.20.
//

//
// Created by Björn Mathis on 07.11.20.
//

#include "../public/include_api.h"
#include "includes.h"
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif


struct stat st = {0};

const int64_t TRIGGEREDUIDSIZE = 1000000;
bool triggered[TRIGGEREDUIDSIZE] = { false };

void signal_triggered_mutation(int64_t UID) {
    if (UID < TRIGGEREDUIDSIZE) {
        if (triggered[UID]) {
            return;
        }
    }
    triggered[UID] = true;
    const char* triggeredFolderPath = getenv("TRIGGERED_FOLDER");
    const char* triggeredOutput = getenv("TRIGGERED_OUTPUT");
    if (!triggeredFolderPath) {
        triggeredFolderPath = "./trigger_signal";
    }
    // check if folder exists, if not create it
    if (stat(triggeredFolderPath, &st) == -1) {
        mkdir(triggeredFolderPath, 0700);
    }
    // check if folder exists now, if so place file in it
    if (stat(triggeredFolderPath, &st) != -1) {
        char* filename = (char*) malloc(strlen(triggeredFolderPath) + 100);
        sprintf(filename, "%s/%" PRId64, triggeredFolderPath, UID);
        open(filename, O_CREAT);
    }
}

int mutate_printf_string(const char *format, ...){
    char *stringbuffer;
    va_list args, reusable_args;
    int sizeofbuffer, printf_ret_val;

    va_start (args, format);
    va_copy(reusable_args, args);
    sizeofbuffer = vsnprintf(stringbuffer, 0, format, args);
    va_end (args);

    stringbuffer = (char*)malloc(sizeofbuffer + 1);
    sizeofbuffer = vsnprintf(stringbuffer, sizeofbuffer + 1, format, reusable_args);

    printf_ret_val = printf(stringbuffer);
    free(stringbuffer);
    return printf_ret_val;
}

int mutate_sprintf_string(char *str, const char *format, ...){
    char *stringbuffer;
    va_list args, reusable_args;
    int sizeofbuffer, sprintf_ret_val;

    va_start (args, format);
    va_copy(reusable_args, args);
    sizeofbuffer = vsnprintf(stringbuffer, 0, format, args);
    va_end (args);

    stringbuffer = (char*)malloc(sizeofbuffer + 1);
    sizeofbuffer = vsnprintf(stringbuffer, sizeofbuffer + 1, format, reusable_args);

    sprintf_ret_val = sprintf(str, stringbuffer);
    free(stringbuffer);
    return sprintf_ret_val;
}


int mutate_snprintf_string(char *str, size_t size, const char *format, ...){
    char *stringbuffer;
    va_list args, reusable_args;
    int sizeofbuffer, printf_ret_val;

    va_start (args, format);
    va_copy(reusable_args, args);
    sizeofbuffer = vsnprintf(stringbuffer, 0, format, args);
    va_end (args);

    stringbuffer = (char*)malloc(sizeofbuffer + 1);
    sizeofbuffer = vsnprintf(stringbuffer, sizeofbuffer + 1, format, reusable_args);

    printf_ret_val = snprintf(str, size, stringbuffer);
    free(stringbuffer);
    return printf_ret_val;
}
#ifdef __cplusplus
}
#endif
