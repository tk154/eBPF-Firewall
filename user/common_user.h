#ifndef BPFW_COMMON_USER_H
#define BPFW_COMMON_USER_H

#include <stdio.h>


extern int fw_log_level;

#define FW_LOG_LEVEL_ERROR   0
#define FW_LOG_LEVEL_WARN    1
#define FW_LOG_LEVEL_INFO    2
#define FW_LOG_LEVEL_DEBUG   3
#define FW_LOG_LEVEL_VERBOSE 4

#define FW_ERROR(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_ERROR) \
        fprintf(stderr, format, ##__VA_ARGS__); } while (0)

#define FW_WARN(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_WARN) \
        fprintf(stderr, format, ##__VA_ARGS__); } while (0)

#define FW_INFO(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_INFO) \
        printf(format, ##__VA_ARGS__); } while (0)

#define FW_DEBUG(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_DEBUG) \
        printf(format, ##__VA_ARGS__); } while (0)

#define FW_VERBOSE(format, ...) \
    do { if (fw_log_level >= FW_LOG_LEVEL_VERBOSE) \
        printf(format, ##__VA_ARGS__); } while (0)


// Used to check and return the error code of a function
#define CHECK_RC(rc) do { \
    int _rc = (rc); if (_rc != 0) return _rc; \
} while (0)


#endif
