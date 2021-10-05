//
// Created by Björn Mathis on 07.11.20.
//

//
// Created by Björn Mathis on 07.11.20.
//

#include "../public/include_api.h"
#include "includes.h"
#include <stdarg.h>
#include <cerrno>

#ifdef __cplusplus
extern "C" {
#endif


struct stat st = {0};

const int64_t TRIGGEREDUIDSIZE = 1000000;
bool triggered[TRIGGEREDUIDSIZE] = { false };

void signal_triggered_mutation(int64_t UID) {
    if (0 <= UID && UID < TRIGGEREDUIDSIZE) {
        if (triggered[UID]) {
            return;
        }
    } else {
        fprintf(stderr, "UID out of range %d\n", UID);
        abort();
    }
    triggered[UID] = true;
    const char* triggeredFolderPath = getenv("TRIGGERED_FOLDER");
    const char* triggeredOutput = getenv("TRIGGERED_OUTPUT");
    if (!triggeredFolderPath) {
        triggeredFolderPath = "./trigger_signal";
    }
    // check if folder exists, if not create it
    if (stat(triggeredFolderPath, &st) == -1) {
        if (mkdir(triggeredFolderPath, 0777) != 0) {
            fprintf(stderr, "Could not create triggered folder path: %s reason: %s\n",
                triggeredFolderPath, strerror(errno));
        }
    }
    // check if folder exists now, if so place file in it
    if (stat(triggeredFolderPath, &st) != -1) {
        char* filename = (char*) malloc(strlen(triggeredFolderPath) + 100);
        sprintf(filename, "%s/%" PRId64, triggeredFolderPath, UID);
        int fd = open(filename, O_CREAT);
        fsync(fd);
        close(fd);
        free(filename);
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

void mutate_delete(void* my_ptr){
    delete my_ptr;
}

#ifdef __cplusplus
}
#endif
