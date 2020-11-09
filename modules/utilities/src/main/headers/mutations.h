//
// Created by Björn Mathis on 11.09.20.
//

#ifndef LLVM_MUTATION_TOOL_MUTATIONS_H
#define LLVM_MUTATION_TOOL_MUTATIONS_H

#define MALLOC 0
#define FGETS_MATCH_BUFFER_SIZE 1
#define SIGNED_LESS_THAN 2
#define SIGNED_GREATER_THAN 3
#define SIGNED_LESS_THAN_EQUALTO 4
#define SIGNED_GREATER_THAN_EQUALTO 5
#define FREE_FUNCTION_ARGUMENT 6
#define PTHREAD_MUTEX 7
#define ATOMIC_CMP_XCHG 8
#define ATOMICRMW_REPLACE 9
#define SIGNED_TO_UNSIGNED 10 // convert a signed comparison to an unsigned one
#define UNSIGNED_TO_SIGNED 11 // convert an unsigned comparison to a signed one
#define SWITCH_SHIFT 12 // switch shift from logical to arithmetic or vice versa
#define CALLOC 13

#endif //LLVM_MUTATION_TOOL_MUTATIONS_H
