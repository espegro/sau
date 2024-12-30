/**
 * sau.c
 *
 * Combined hooking library for logging:
 *   - connect() calls
 *   - execve() calls
 *
 * Compile:
 *   gcc -fPIC -shared -o libsau.so sau.c -ldl -lcrypto
 *
 * Usage:
 *   Place libsau.so in a secure directory, e.g., /opt/sau_hooks/
 *   Configure LD_PRELOAD for sshd in its service override file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <errno.h>

// Function pointers for original functions
static int (*real_connect)(int, const struct sockaddr*, socklen_t) = NULL;
static int (*real_execve)(const char*, char* const[], char* const[]) = NULL;

// Utility: Resolve username
static const char* resolve_username(uid_t uid) {
    struct passwd* pw = getpwuid(uid);
    return pw ? pw->pw_name : "unknown";
}

// Utility: Compute SHA-256 hash of a file
static const char* compute_sha256(const char* file_path) {
    static char hash_str[65];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        snprintf(hash_str, sizeof(hash_str), "unreadable");
        return hash_str;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }
    fclose(file);

    SHA256_Final(hash, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hash_str + (i * 2), 3, "%02x", hash[i]);
    }
    return hash_str;
}

// Utility: Build command-line string
static char* build_command_line(char* const argv[]) {
    static char command_line[1024];
    command_line[0] = '\0';

    if (argv) {
        for (int i = 0; argv[i] != NULL; i++) {
            if (strlen(command_line) + strlen(argv[i]) + 1 < sizeof(command_line)) {
                strncat(command_line, argv[i], sizeof(command_line) - strlen(command_line) - 1);
                if (argv[i + 1]) {
                    strncat(command_line, " ", sizeof(command_line) - strlen(command_line) - 1);
                }
            } else {
                strncat(command_line, " [TRUNCATED]", sizeof(command_line) - strlen(command_line) - 1);
                break;
            }
        }
    }

    return command_line;
}

// Resolve the current library's path dynamically
static char *resolve_library_path() {
    static char library_path[1024] = {0};
    Dl_info dl_info;

    if (dladdr((void *)resolve_library_path, &dl_info) != 0 && dl_info.dli_fname) {
        strncpy(library_path, dl_info.dli_fname, sizeof(library_path) - 1);
    } else {
        syslog(LOG_ERR, "[sau] Failed to resolve library path");
        library_path[0] = '\0';
    }

    return library_path;
}

// Add LD_PRELOAD for interactive shells and common tools
static char **add_ld_preload_if_interactive(const char *filename, char *const envp[]) {
    static char new_ld_preload[1024];
    static char *new_env[1024];
    const char *self_preload = resolve_library_path();

    if (!self_preload || self_preload[0] == '\0') {
        syslog(LOG_ERR, "[sau] Could not resolve the library path for LD_PRELOAD");
        return (char **)envp; // Fallback to original environment
    }

    // Detect if the filename is an interactive shell or common tool
    if (strstr(filename, "bash") || strstr(filename, "zsh") || strstr(filename, "sh") ||
        strstr(filename, "python") || strstr(filename, "perl") || strstr(filename, "ruby") ||
        strstr(filename, "php") || strstr(filename, "nc") || strstr(filename, "socat")) {

        int i = 0, j = 0;
        for (i = 0; envp && envp[i]; i++) {
            if (strncmp(envp[i], "LD_PRELOAD=", 11) == 0) {
                snprintf(new_ld_preload, sizeof(new_ld_preload), "LD_PRELOAD=%s:%s",
                         envp[i] + 11, self_preload);
                new_env[j++] = new_ld_preload;
            } else {
                new_env[j++] = envp[i];
            }
        }

        if (!getenv("LD_PRELOAD")) {
            snprintf(new_ld_preload, sizeof(new_ld_preload), "LD_PRELOAD=%s", self_preload);
            new_env[j++] = new_ld_preload;
        }

        new_env[j] = NULL; // Null-terminate
        return new_env;
    }

    return (char **)envp; // Do not modify environment if not interactive or a common tool
}

// Hooked connect() function
int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    int result = real_connect(sockfd, addr, addrlen);
    int saved_errno = errno;

    if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        int port;

        if (addr->sa_family == AF_INET) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, sizeof(ip_str));
            port = ntohs(addr_in->sin_port);
        } else {
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(addr_in6->sin6_port);
        }

        uid_t uid = getuid();
        const char* username = resolve_username(uid);
        pid_t sid = getsid(0);
        pid_t ppid = getppid();
        syslog(LOG_NOTICE, "[sau] connect() - USER=%s PID=%d SID=%d PPID=%d to %s:%d (result=%d, errno=%d)",
               username, getpid(), sid, ppid, ip_str, port, result, saved_errno);
    }

    errno = saved_errno;
    return result;
}

// Hooked execve() function
int execve(const char *filename, char *const argv[], char *const envp[]) {
    if (!real_execve) {
        real_execve = dlsym(RTLD_NEXT, "execve");
        if (!real_execve) {
            syslog(LOG_ERR, "[sau] execve() hook called before initialization");
            errno = EACCES;
            return -1;
        }
    }

    // Add LD_PRELOAD if the process is interactive or a common tool
    char **new_envp = add_ld_preload_if_interactive(filename, envp);

    // Log the execve call
    uid_t uid = getuid();
    const char *username = resolve_username(uid);
    const char *sha256 = compute_sha256(filename);
    const char *cmd_line = build_command_line(argv);
    pid_t sid = getsid(0);
    pid_t ppid = getppid();
    syslog(LOG_NOTICE, "[sau] execve() - USER=%s UID=%d SID=%d PPID=%d CMD=[%s] FILE=[%s] SHA256=[%s]",
           username, uid, sid, ppid, cmd_line, filename, sha256);

    return real_execve(filename, argv, new_envp);
}

// Constructor and Destructor
__attribute__((constructor))
static void init_hooks() {
    openlog("sau", LOG_PID | LOG_NDELAY, LOG_AUTH);
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_execve = dlsym(RTLD_NEXT, "execve");
    if (!real_connect || !real_execve) {
        syslog(LOG_ERR, "[sau] Failed to resolve real functions: %s", dlerror());
        _exit(1);
    }
}

__attribute__((destructor))
static void cleanup_hooks() {
    closelog();
}
