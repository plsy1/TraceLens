#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    void *library;
    printf("%d\n", getpid());
    fflush(stdout);
    sleep(1);
    library = dlopen("libssl.so.3", RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fputs(dlerror(), stderr);
        return 1;
    }
    sleep(6);
    dlclose(library);
    return 0;
}
