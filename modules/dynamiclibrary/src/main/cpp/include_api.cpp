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

void signal_triggered_mutation(int64_t UID) {
    const char* triggeredFilePath = getenv("TRIGGERED_FILE");
    const char* triggeredOutput = getenv("TRIGGERED_OUTPUT");
    if (triggeredFilePath) {
        FILE* triggeredFile = fopen(triggeredFilePath, "w");
        if (triggeredFile) {
            if (triggeredOutput) {
                fputs(triggeredOutput, triggeredFile);
                sprintf(sprintfbuffer, "\nUID %lld\n", UID);
                fputs(sprintfbuffer, triggeredFile);
            } else {
                fputs("Triggered!", triggeredFile);
                sprintf(sprintfbuffer, "\nUID %lld\n", UID);
                fputs(sprintfbuffer, triggeredFile);
            }
        }
    }
    if (triggeredOutput) {
        printf("%s\nUID %lld\n", triggeredOutput, UID);
    } else {
        printf("Triggered!\nUID %lld\n", UID);
    }
}

#ifdef __cplusplus
}
#endif
