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


struct stat st = {0};

const int64_t TRIGGEREDUIDSIZE = 1000000;
bool triggered[TRIGGEREDUIDSIZE] = { false };

void signal_triggered_mutation(int64_t UID) {
    if (UID < TRIGGEREDUIDSIZE) {
        if (triggered[UID]) {
            return;
        }
    } else {
        return;
    }
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

#ifdef __cplusplus
}
#endif
