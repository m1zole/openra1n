#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#define RESET_COLOR   "\033[0m"
#define RED_COLOR     "\033[31m"
#define GREEN_COLOR   "\033[32m"
#define YELLOW_COLOR  "\033[33m"
#define BLUE_COLOR    "\033[34m"
#define MAGENTA_COLOR "\033[35m"
#define CYAN_COLOR    "\033[36m"
#define WHITE_COLOR   "\033[37m"
#define GRAY_COLOR    "\033[90m"

#define RAINBOW_COLORS \
    {RED_COLOR, GREEN_COLOR, YELLOW_COLOR, BLUE_COLOR, MAGENTA_COLOR, CYAN_COLOR}

// style: [INFO] (filename:line) --> message
#define LOG(fmt, ...) \
    printf(CYAN_COLOR "[INFO] " BLUE_COLOR "(%s:%d)" GRAY_COLOR " --> " CYAN_COLOR fmt RESET_COLOR "\n", \
           __FILE__, __LINE__, ##__VA_ARGS__)

#define ERR(fmt, ...) \
    printf(RED_COLOR "[ERROR] " BLUE_COLOR "(%s:%d)" GRAY_COLOR " --> " RED_COLOR fmt RESET_COLOR "\n", \
           __FILE__, __LINE__, ##__VA_ARGS__)

// log_rainbow: just print out the message with every character a different color
#define LOG_RAINBOW(fmt, ...) do { \
    const char *colors[] = RAINBOW_COLORS; \
    int n = sizeof(colors) / sizeof(colors[0]); \
    for (int i = 0; fmt[i]; ++i) { \
        printf("%s%c", colors[i % n], fmt[i]); \
    } \
    printf(RESET_COLOR "\n"); \
} while (0)

#ifdef DEVBUILD
#define DEVLOG(fmt, ...) \
    printf(WHITE_COLOR "[DEBUG] " BLUE_COLOR "(%s:%d)" GRAY_COLOR " --> " WHITE_COLOR fmt RESET_COLOR "\n", \
           __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DEVLOG(fmt, ...)
#endif

#endif  // LOG_H
