#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif 

#ifdef __clang__
typedef __mode_t mode_t;
#endif

int mkpath(const char *path, mode_t mode);

#ifdef __cplusplus
}
#endif 

