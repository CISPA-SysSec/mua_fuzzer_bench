#include <stdio.h>
#include <stdlib.h>

#include <stddef.h>
#include <stdint.h>
#include <queue>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {

    std::ifstream file(argv[1]);
    if (file)
    {
        /*
         * Get the size of the file
         */
        file.seekg(0,std::ios::end);
        std::streampos length = file.tellg();
        file.seekg(0,std::ios::beg);

        /*
         * Use a vector as the buffer.
         * It is exception safe and will be tidied up correctly.
         * This constructor creates a buffer of the correct length.
         * Because char is a POD data type it is not initialized.
         *
         * Then read the whole file into the buffer.
         */
        std::vector<char> buffer(length);
        file.read(&buffer[0],length);

        /* Call function to be fuzzed, e.g.: */
        LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(buffer.data()), length);
    }

    return 0;
}
