#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUFFER_LEN (1024 * (EVENT_SIZE + 16))

int monitor_directory(const char *path) {
    int fd = inotify_init();
    if(fd < 0) {
        perror("Failed to initialize inotify");
        return -1;
    }
    int wd = inotify_add_watch(fd, path, IN_CREATE);
    if(wd < 0) {
        perror("Failed to add watch");
        close(fd);
        return -1;
    }
    printf("Monitoring directory: %s\n", path);
    char buffer[BUFFER_LEN];

    while(true) {
        int length = read(fd, buffer, BUFFER_LEN);
        if(length < 0) {
            perror("Failed to read events");
            break;
        }
        int i = 0;
        while(i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if(event -> len) {
                if(event -> mask & IN_CREATE) {
                    printf("File created: %s%s\n", path, event -> name);
                    return 1;
                }
            }
            i += EVENT_SIZE + event -> len;
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
int monitor_directory(const char *path);

#ifdef __cplusplus
}
#endif