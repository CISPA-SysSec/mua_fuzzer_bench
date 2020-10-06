#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

int AVAILABLE = 42;
int BLA = 2;
int LOCKED = 36;

// The data each thread gets to do its work.
struct thread_data {
    int num;
    int total_threads;
    char* data;
    int data_len;
    char** out;
    int* mutex;
};

// The function each thread executes
void* worker(void * tdata) {
    // cast the void pointer to the thread_data struct
    struct thread_data* info = (struct thread_data*)tdata;

    /* printf("%p %d %p %d\n", tdata, info->num, info->data, info->data_len); */

    // Do some useless work on the data, in a way that would create a race
    // condition without the locks.
    for (int ii = info->num; ii < info->data_len; ii = ii + info->total_threads) {

        /* printf("%d: %d %c\n", info->num, ii, info->data[ii]); */

        // Get lock
        // Mutation: remove the locking code, this should reintroduce race
        // conditions
        while (1) {
            int expected = AVAILABLE;
            if (__atomic_compare_exchange(info->mutex, &expected, &LOCKED, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                break;
            }
        }

        // Copy a input byte to the output
        char* addr = *info->out;
        useconds_t sleep_time = rand() % 100;
        usleep(sleep_time);
        *addr = info->data[ii];
        *info->out = addr + 1;

        // Release lock
        __atomic_store(info->mutex, &AVAILABLE, __ATOMIC_SEQ_CST);
    }

    // The caller does not clean up the memory, so do it here.
    free(tdata);

    // Return value is ignored
    return NULL;
}

// Get and set up threads and user data.
int main() {
    srand(time(NULL));
    // Get the number of threads to work with
    #define THRD_INP_SIZE 16
    // Get the user input that specifies the number of threads
    char* thread_num_data = (char*)calloc(THRD_INP_SIZE, 1);
    fgets(thread_num_data, THRD_INP_SIZE, stdin);
    // Convert the user string to a long
    char* end = thread_num_data + strlen(thread_num_data);
    long num_threads = strtol(thread_num_data, &end, 10);
    // Clean up tmp buf
    free(thread_num_data);
    thread_num_data = NULL;

    // Check that num threads is acceptable
    printf("num threads %ld\n", num_threads);
    if (num_threads < 1 || num_threads > 16) {
        return 1;
    }

    // Get the data to execute on
    #define INP_SIZE 1024
    char* data = (char*)calloc(1, INP_SIZE);
    fgets(data, INP_SIZE, stdin);

    // print the input again
    printf("%lu, %s\n", strnlen(data, INP_SIZE), data);

    // get length of input (this includes a possible linebreak)
    int data_len = strnlen(data, INP_SIZE);

    // allocate memory to write the output
    char* out = (char*)calloc(INP_SIZE, 1);
    char* initial_out = out;

    // Set up array to store info on started threads
    pthread_t thread_id[16] = {0};

    // Initialize atomically used int to act as mutex
    int mutex = AVAILABLE;

    // Start the specified number of threads
    for (int i=0; i < num_threads; ++i) {
        // Each gets a copy of the thread_data, that is freed inside the thread.
        struct thread_data* tdata = (struct thread_data*)calloc(sizeof(struct thread_data), 1);
        tdata->num = i;
        tdata->total_threads = num_threads;
        tdata->data = data;
        tdata->data_len = data_len;
        tdata->out = &out;
        tdata->mutex = &mutex;

        // Start the thread
        if (pthread_create(&thread_id[i], NULL, worker, tdata) != 0) {
            printf("%d-th thread creation error\n", i);
            return 2;
        }
    }

    // Wait for all threads to finish
    for (int i=0; i < num_threads; ++i) {
        if (pthread_join(thread_id[i], NULL) != 0) {
            printf("%d-th thread join error\n", i);
            return 3;
        }
    }

    // Print the resulting output
    printf("%lu, %s\n", strnlen(initial_out, INP_SIZE), initial_out);

    // Clean up the remaining allocated data
    free(data);
    data = NULL;

    free(initial_out);
    initial_out = NULL;
}
