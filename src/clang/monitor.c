#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUFFER_LEN (1024 * (EVENT_SIZE + 16))

volatile sig_atomic_t monitor_running = 0;
int global_fd = -1;
int global_wd = -1;

typedef struct {
    char path[256];
    void (*callback)(const char*, const char*);
} MonitorContext;

void stop_monitoring(int signum) {
    printf("Stopping directory monitoring...\n");
    monitor_running = 0;
    if (global_wd != -1) inotify_rm_watch(global_fd, global_wd);
    if (global_fd != -1) close(global_fd);
}

int monitor_directory(const char *path, void (*callback)(const char*, const char*)) {
    signal(SIGINT, stop_monitoring);
    signal(SIGTERM, stop_monitoring);

    monitor_running = 1;
    global_fd = -1;
    global_wd = -1;

    int fd = inotify_init();
    if (fd < 0) {
        perror("Failed to initialize inotify");
        return -1;
    }
    global_fd = fd;

    int wd = inotify_add_watch(fd, path, 
        IN_CREATE |    
        IN_DELETE |    
        IN_MODIFY |    
        IN_MOVED_FROM | 
        IN_MOVED_TO
    );
    if (wd < 0) {
        perror("Failed to add watch");
        close(fd);
        return -1;
    }
    global_wd = wd;

    printf("Monitoring directory: %s\n", path);
    char buffer[BUFFER_LEN];

    while (monitor_running) {
        fd_set read_fds;
        struct timeval timeout;
        
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        
        timeout.tv_sec = 1; 
        timeout.tv_usec = 0;
        int ready = select(fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            perror("Select error");
            break;
        }
        if (ready == 0) continue;
        int length = read(fd, buffer, BUFFER_LEN);
        if (length < 0) {
            perror("Failed to read events");
            break;
        }
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            if (event -> len) {
                if (event -> mask & IN_CREATE) {
                    if (callback) callback(path, event -> name);
                    printf("Created: %s/%s\n", path, event -> name);
                }
                if (event -> mask & IN_DELETE) {
                    if (callback) callback(path, event -> name);
                    printf("Deleted: %s/%s\n", path, event -> name);
                }
                if (event -> mask & IN_MODIFY) {
                    if (callback) callback(path, event -> name);
                    printf("Modified: %s/%s\n", path, event -> name);
                }
                if (event -> mask & IN_MOVED_FROM) {
                    if (callback) callback(path, event -> name);
                    printf("Moved from: %s/%s\n", path, event -> name);
                }
                if (event -> mask & IN_MOVED_TO) {
                    if (callback) callback(path, event -> name);
                    printf("Moved to: %s/%s\n", path, event -> name);
                }
            }
            i += EVENT_SIZE + event -> len;
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    printf("Monitoring stopped for %s\n", path);
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
int monitor_directory(const char *path);
#ifdef __cplusplus
}
#endif