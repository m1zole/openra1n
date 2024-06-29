#include <common/log.h>
#include <common/common.h>

#include <errno.h>
#include <fcntl.h>              // open
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>             // exit, strtoull
#include <string.h>             // strlen, strerror, memcpy, memmove
#include <unistd.h>             // close
#include <wordexp.h>
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstst
#include <getopt.h>

bool use_autoboot = false;
bool use_safemode = false;
bool use_verbose_boot = false;
bool use_legacy   = false;
bool use_kok3shi9 = false;

char* bootArgs = NULL;
char *override_pongo = NULL;
char *override_kpf = NULL;
char *override_ramdisk = NULL;
char *override_overlay = NULL;

unsigned char *load_pongo = NULL;
unsigned int load_pongo_len = 0;
unsigned char *load_kpf = NULL;
unsigned int load_kpf_len = 0;
unsigned char *load_ramdisk = NULL;
unsigned int load_ramdisk_len = 0;
unsigned char *load_overlay = NULL;
unsigned int load_overlay_len = 0;

override_file_t override_file(const char* file)
{
    override_file_t ret;
    FILE *fp = fopen(file, "rb");
    if (fp == NULL) {
        ERR("File doesn't find.\n");
        ret.len = 0;
        ret.ptr = NULL;
        return ret;
    }
    fseek(fp, 0, SEEK_END);
    ret.len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    ret.ptr = malloc(ret.len);
    fread(ret.ptr, ret.len, 1, fp);
    fclose(fp);
    return ret;
}

#ifdef DEVBUILD
static inline __attribute__((always_inline))  void usage(const char* s)
{
    printf("Usage: %s [-ahsv] [-e <boot-args>]\n", s);
    printf("\t-h, --help\t\t\t: show usage\n");
    printf("\t-a, --autoboot\t\t\t: enable bakera1n boot mode\n");
    printf("\t-e, --extra-bootargs <args>\t: replace bootargs\n");
    printf("\t-s, --safemode\t\t\t: enable safe mode\n");
    printf("\t-v, --verbose-boot\t\t: enable verbose boot\n");
    
    return;
}

int main(int argc, char** argv)
{
    int opt = 0;
    static struct option longopts[] = {
        { "openra1n",               no_argument,       NULL, 'O' },
        { "pongoterm",              no_argument,       NULL, 'P' },
        { "help",                   no_argument,       NULL, 'h' },
        { "autoboot",               no_argument,       NULL, 'a' },
        { "extra-bootargs",         required_argument, NULL, 'e' },
        { "safemode",               no_argument,       NULL, 's' },
        { "legacy",                 no_argument,       NULL, 'l' },
        { "kok3shi9",               no_argument,       NULL, '9' },
        { "verbose-boot",           no_argument,       NULL, 'v' },
        { "override-kpf",           required_argument, NULL, 'K' },
        { "override-ramdisk",       required_argument, NULL, 'r' },
        { "override-overlay",       required_argument, NULL, 'o' },
        { "override-pongo",         required_argument, NULL, 'k' },
        { NULL, 0, NULL, 0 }
    };
    
    int mode = 0;
    
    while ((opt = getopt_long(argc, argv, "OPalh9K:e:svk:r:o:i:", longopts, NULL)) > 0) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                return 0;
                
            case 'O':
                LOG("selected: openra1n mode");
                mode = 1;
                break;
                
            case 'P':
                LOG("selected: pongoterm mode");
                mode = 2;
                break;
                
            case 'a':
                use_autoboot = 1;
                LOG("selected: autoboot mode");
                break;

            case 'e':
                if (optarg) {
                    bootArgs = strdup(optarg);
                    LOG("set bootArgs: [%s]", bootArgs);
                }
                break;

            case 's':
                use_safemode = 1;
                break;
                
            case 'v':
                use_verbose_boot = 1;
                break;

            case 'k':
                override_pongo = strdup(optarg);
                LOG("pongo:   [%s]", override_pongo);
                break;

            case 'K':
                override_kpf = strdup(optarg);
                LOG("kpf:     [%s]", override_kpf);
                break;

            case 'r':
                override_ramdisk = strdup(optarg);
                LOG("ramdisk: [%s]", override_ramdisk);
                break;

            case 'o':
                override_overlay = strdup(optarg);
                LOG("overlay: [%s]", override_overlay);
                break;

            case '9':
                use_kok3shi9 = 1;
                break;

            case 'l':
                use_legacy = 1;
                break;

            default:
                break;
        }
    }
    
    if (mode != 2)
    {
        openra1n(0, NULL);
        usleep(5000);
    }
    if (mode != 1)
    {
        pongoterm(0, NULL);
    }
}
#endif
