#ifndef LOG_H
#define LOG_H

#define MAX_LOG_SIZE 119

enum log_level { DEBUG, INFORMATION, WARNING, ERROR };

void npt_log_init(const char *);
void npt_log_close(void);
void npt_log(int, const char *, ...);

#define log(...) npt_log( __VA_ARGS__ )
#define log_debug(...) log(DEBUG, __VA_ARGS__)
#define log_warning(...) log(WARNING, __VA_ARGS__)
#define log_error(...) log(ERROR, __VA_ARGS__)
#define log_info(...) log(INFORMATION, __VA_ARGS__)

#endif
