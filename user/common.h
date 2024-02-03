#ifndef USER_COMMON_H
#define USER_COMMON_H

#include <stdio.h>


#define FW_LOG_LEVEL_ERROR 0
#define FW_LOG_LEVEL_WARN  1
#define FW_LOG_LEVEL_INFO  2
#define FW_LOG_LEVEL_DEBUG 3

#if FW_LOG_LEVEL >= FW_LOG_LEVEL_ERROR
#define FW_ERROR(...) fprintf(stderr, __VA_ARGS__)
#else
#define FW_ERROR(...)
#endif

#if FW_LOG_LEVEL >= FW_LOG_LEVEL_WARN
#define FW_WARN(...) fprintf(stderr, __VA_ARGS__)
#else
#define FW_WARN(...)
#endif

#if FW_LOG_LEVEL >= FW_LOG_LEVEL_INFO
#define FW_INFO(...) printf(__VA_ARGS__)
#else
#define FW_INFO(...)
#endif

#if FW_LOG_LEVEL >= FW_LOG_LEVEL_DEBUG
#define FW_DEBUG(...) printf(__VA_ARGS__)
#else
#define FW_DEBUG(...)
#endif

#endif
