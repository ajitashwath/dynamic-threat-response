#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#define MAX_PATH_LENGTH 1024

volatile sig_atomic_t monitor_running = 0;
HANDLE global_dir_handle = NULL;

typedef struct {
    char path[MAX_PATH_LENGTH];
    void (*callback)(const char*, const char*);
} MonitorContext;

void stop_monitoring(int signum) {
    printf("Stopping directory monitoring...\n");
    monitor_running = 0;
}

int monitor_directory(const char *path, void (*callback)(const char*, const char*)) {
    signal(SIGINT, stop_monitoring);
    signal(SIGTERM, stop_monitoring);

    monitor_running = 1;
    wchar_t w_path[MAX_PATH_LENGTH];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w_path, MAX_PATH_LENGTH);

    HANDLE dir_handle = CreateFileW(
        w_path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (dir_handle == INVALID_HANDLE_VALUE) {
        printf("Failed to open directory: %s\n", path);
        return -1;
    }

    global_dir_handle = dir_handle;
    BYTE buffer[1024 * sizeof(FILE_NOTIFY_INFORMATION)];
    DWORD bytes_returned;

    printf("Monitoring directory: %s\n", path);

    while (monitor_running) {
        if (ReadDirectoryChangesW(
            dir_handle,
            buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | 
            FILE_NOTIFY_CHANGE_DIR_NAME | 
            FILE_NOTIFY_CHANGE_ATTRIBUTES | 
            FILE_NOTIFY_CHANGE_SIZE | 
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes_returned,
            NULL,
            NULL
        ) == 0) {
            printf("ReadDirectoryChangesW failed\n");
            break;
        }

        PFILE_NOTIFY_INFORMATION notify = (PFILE_NOTIFY_INFORMATION)buffer;
        while (TRUE) {
            wchar_t filename[MAX_PATH];
            wcscpy_s(filename, MAX_PATH, notify -> FileName);

            char utf8_filename[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, filename, -1, utf8_filename, MAX_PATH, NULL, NULL);
            switch (notify -> Action) {
                case FILE_ACTION_ADDED:
                    printf("Created: %s/%s\n", path, utf8_filename);
                    if (callback) callback(path, utf8_filename);
                    break;
                case FILE_ACTION_REMOVED:
                    printf("Deleted: %s/%s\n", path, utf8_filename);
                    if (callback) callback(path, utf8_filename);
                    break;
                case FILE_ACTION_MODIFIED:
                    printf("Modified: %s/%s\n", path, utf8_filename);
                    if (callback) callback(path, utf8_filename);
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                    printf("Renamed from: %s/%s\n", path, utf8_filename);
                    if (callback) callback(path, utf8_filename);
                    break;
                case FILE_ACTION_RENAMED_NEW_NAME:
                    printf("Renamed to: %s/%s\n", path, utf8_filename);
                    if (callback) callback(path, utf8_filename);
                    break;
            }

            if (notify->NextEntryOffset == 0) break;
            notify = (PFILE_NOTIFY_INFORMATION)((BYTE*)notify + notify -> NextEntryOffset);
        }
    }
    CloseHandle(dir_handle);
    global_dir_handle = NULL;
    printf("Monitoring stopped for %s\n", path);
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
int monitor_directory(const char *path, void (*callback)(const char*, const char*));
#ifdef __cplusplus
}
#endif