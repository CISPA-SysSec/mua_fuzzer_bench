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

#ifdef __cplusplus
}
#endif

#endif //LLVM_MUTATION_TOOL_INCLUDES_H
