//
// Created by Björn Mathis on 07.11.20.
//

#ifndef LLVM_MUTATION_TOOL_INCLUDE_API_H
#define LLVM_MUTATION_TOOL_INCLUDE_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    void signal_triggered_mutation(int64_t UID);
    int mutate_printf_string(const char *format, ...);
    int mutate_sprintf_string(char *str, const char *format, ...);
    int mutate_snprintf_string(char *str, size_t size, const char *format, ...);
    void mutate_delete(void* my_ptr);
    uint64_t mutate_square_add(uint64_t value);
    uint64_t mutate_root_half_sub(uint64_t value);
#ifdef __cplusplus
}
#endif

#endif //LLVM_MUTATION_TOOL_INCLUDES_H
