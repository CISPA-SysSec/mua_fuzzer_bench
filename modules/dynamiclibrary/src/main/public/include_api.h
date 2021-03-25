//
// Created by Björn Mathis on 07.11.20.
//

#ifndef LLVM_MUTATION_TOOL_INCLUDE_API_H
#define LLVM_MUTATION_TOOL_INCLUDE_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    void signal_triggered_mutation(int64_t UID);
    int mutate_printf_string(const char *format, ...);
    int mutate_sprintf_string(char *str, const char *format, ...);
    // int mutate_fprintf_string(FILE *stream, const char *format, ...);
#ifdef __cplusplus
}
#endif

#endif //LLVM_MUTATION_TOOL_INCLUDES_H
