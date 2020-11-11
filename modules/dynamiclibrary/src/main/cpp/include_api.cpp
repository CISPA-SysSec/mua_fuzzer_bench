//
// Created by Björn Mathis on 07.11.20.
//

//
// Created by Björn Mathis on 07.11.20.
//

#include "../public/include_api.h"
#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

void signal_triggered_mutation() {
    const char* triggeredFilePath = getenv("TRIGGERED_FILE");
    const char* triggeredOutput = getenv("TRIGGERED_OUTPUT");
    if (triggeredFilePath) {
        FILE* triggeredFile = fopen(triggeredFilePath, "w");
        if (triggeredFile) {
            if (triggeredOutput) {
                fputs(triggeredOutput, triggeredFile);
                fputs("\n", triggeredFile);
            } else {
                fputs("Triggered!\n", triggeredFile);
            }
        }
    }
    if (triggeredOutput) {
        printf("%s\n", triggeredOutput);
    } else {
        printf("Triggered!\n");
    }
}

#ifdef __cplusplus
}
#endif
