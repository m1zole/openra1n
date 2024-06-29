#include <stdbool.h>
#include <stdint.h>

//thanks to palera1n!
//https://github.com/palera1n/palera1n/blob/main/include/palerain.h#L143
typedef struct {
    unsigned char* ptr; /* pointer to the override file in memory */
    uint32_t len; /* length of override file */
} override_file_t;

int pongoterm(int argc, char** argv);
int openra1n(int argc, char **argv);
override_file_t override_file(const char* file);

