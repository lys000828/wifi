/**
 * Native hook module - intercepts libc calls to hide root and spoof MAC.
 * Loaded by Xposed module via System.loadLibrary().
 *
 * Hooks: open, openat, access, stat, lstat, fopen, ioctl,
 *        __system_property_get, popen, readlinkat
 */
#define _GNU_SOURCE
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/system_properties.h>

#include "plt_hook.h"

#define TAG "NativeHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// Spoofed values (set from Java side)
static char g_fake_mac[18] = "AA:BB:CC:DD:EE:FF";
static unsigned char g_fake_mac_bytes[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static char g_fake_ip[16] = "192.168.1.100";
static char g_fake_gateway[16] = "192.168.1.1";
static char g_fake_ssid[64] = "MyHomeWiFi";

// Root paths to hide
static const char *ROOT_PATHS[] = {
    "/system/app/Superuser.apk", "/system/app/Superuser",
    "/system/xbin/su", "/system/bin/su", "/sbin/su",
    "/data/local/xbin/su", "/data/local/bin/su",
    "/system/sd/xbin/su", "/system/bin/failsafe/su",
    "/data/local/su", "/su/bin/su", "/su/bin", "/su",
    "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
    "/system/bin/magisk", "/system/xbin/magisk",
    "/cache/.disable_magisk", "/dev/.magisk.unblock",
    "/data/adb/magisk.img", "/data/adb/magisk.db",
    "/data/magisk.apk", "/system/bin/daemonsu",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/xbin/daemonsu", "/system/xbin/busybox",
    "/system/bin/.ext/.su", "/data/adb/ksu",
    "/data/adb/ksud", "/data/adb/lspd",
    NULL
};

// Sensitive proc/sys paths
static int is_mac_path(const char *path) {
    if (!path) return 0;
    if (strstr(path, "/sys/class/net/") && strstr(path, "/address")) return 1;
    return 0;
}

static int is_root_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; ROOT_PATHS[i]; i++) {
        if (strcmp(path, ROOT_PATHS[i]) == 0) return 1;
    }
    // Pattern matching
    if ((strstr(path, "/su") || strstr(path, "magisk") || strstr(path, "supersu")
         || strstr(path, "busybox") || strstr(path, "xposed")
         || strstr(path, "lsposed") || strstr(path, "edxposed")
         || strstr(path, "riru") || strstr(path, "zygisk"))
        && (strncmp(path, "/system", 7) == 0 || strncmp(path, "/sbin", 5) == 0
            || strncmp(path, "/data/adb", 9) == 0 || strncmp(path, "/data/local", 11) == 0
            || strncmp(path, "/su", 3) == 0 || strncmp(path, "/cache", 6) == 0)) {
        return 1;
    }
    return 0;
}

static int is_sensitive_proc_path(const char *path) {
    if (!path) return 0;
    if (strcmp(path, "/proc/net/arp") == 0) return 1;
    if (strcmp(path, "/proc/net/if_inet6") == 0) return 1;
    if (strstr(path, "/proc/") && strstr(path, "/maps")) return 1;
    if (strstr(path, "/proc/") && strstr(path, "/mountinfo")) return 1;
    if (strcmp(path, "/proc/mounts") == 0) return 1;
    return 0;
}

// ===================== Original function pointers =====================
static int (*orig_open)(const char *, int, ...) = NULL;
static int (*orig_openat)(int, const char *, int, ...) = NULL;
static int (*orig_access)(const char *, int) = NULL;
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static int (*orig_ioctl)(int, int, ...) = NULL;
static int (*orig___system_property_get)(const char *, char *) = NULL;
static FILE *(*orig_popen)(const char *, const char *) = NULL;
static ssize_t (*orig_readlinkat)(int, const char *, char *, size_t) = NULL;

// ===================== Temp file for fake MAC =====================
static char g_fake_mac_tmpfile[256] = {0};
static char g_fake_arp_tmpfile[256] = {0};
static char g_fake_maps_tmpfile[256] = {0};

static void create_fake_mac_file() {
    if (g_fake_mac_tmpfile[0] != '\0') return;
    snprintf(g_fake_mac_tmpfile, sizeof(g_fake_mac_tmpfile), "/data/local/tmp/.nm_%d", getpid());
    FILE *f = fopen(g_fake_mac_tmpfile, "w");
    if (f) {
        char lower_mac[18];
        for (int i = 0; i < 17 && g_fake_mac[i]; i++) {
            lower_mac[i] = (g_fake_mac[i] >= 'A' && g_fake_mac[i] <= 'F')
                           ? g_fake_mac[i] + 32 : g_fake_mac[i];
        }
        lower_mac[17] = '\0';
        fprintf(f, "%s\n", lower_mac);
        fclose(f);
    }
}

static void create_fake_arp_file() {
    if (g_fake_arp_tmpfile[0] != '\0') return;
    snprintf(g_fake_arp_tmpfile, sizeof(g_fake_arp_tmpfile), "/data/local/tmp/.na_%d", getpid());
    FILE *f = fopen(g_fake_arp_tmpfile, "w");
    if (f) {
        fprintf(f, "IP address       HW type     Flags       HW address            Mask     Device\n");
        char lower_mac[18];
        for (int i = 0; i < 17 && g_fake_mac[i]; i++) {
            lower_mac[i] = (g_fake_mac[i] >= 'A' && g_fake_mac[i] <= 'F')
                           ? g_fake_mac[i] + 32 : g_fake_mac[i];
        }
        lower_mac[17] = '\0';
        fprintf(f, "%s     0x1         0x2         %s     *        wlan0\n", g_fake_gateway, lower_mac);
        fclose(f);
    }
}

// Filter /proc/self/maps to remove xposed/magisk references
static void create_fake_maps_file(const char *real_path) {
    if (g_fake_maps_tmpfile[0] != '\0') {
        unlink(g_fake_maps_tmpfile);
    }
    snprintf(g_fake_maps_tmpfile, sizeof(g_fake_maps_tmpfile), "/data/local/tmp/.mp_%d", getpid());

    FILE *real_fp = NULL;
    if (orig_fopen) {
        real_fp = orig_fopen(real_path, "r");
    }
    if (!real_fp) return;

    FILE *fake_fp = fopen(g_fake_maps_tmpfile, "w");
    if (!fake_fp) { fclose(real_fp); return; }

    char line[512];
    while (fgets(line, sizeof(line), real_fp)) {
        // Filter out lines containing root/xposed signatures
        int skip = 0;
        if (strstr(line, "xposed") || strstr(line, "Xposed") ||
            strstr(line, "magisk") || strstr(line, "Magisk") ||
            strstr(line, "supersu") || strstr(line, "SuperSU") ||
            strstr(line, "substrate") || strstr(line, "lsposed") ||
            strstr(line, "LSPosed") || strstr(line, "edxposed") ||
            strstr(line, "riru") || strstr(line, "zygisk") ||
            strstr(line, "libxposed") || strstr(line, "liblspd") ||
            strstr(line, "libriru") || strstr(line, "libzygisk")) {
            skip = 1;
        }
        if (!skip) {
            fputs(line, fake_fp);
        }
    }
    fclose(real_fp);
    fclose(fake_fp);
}

// ===================== Hook implementations =====================

static int hook_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    if (pathname) {
        // Root path -> ENOENT
        if (is_root_path(pathname)) {
            errno = ENOENT;
            return -1;
        }
        // MAC sysfs -> redirect to fake file
        if (is_mac_path(pathname)) {
            create_fake_mac_file();
            if (g_fake_mac_tmpfile[0]) {
                return orig_open(g_fake_mac_tmpfile, O_RDONLY, 0);
            }
        }
        // /proc/net/arp -> fake
        if (strcmp(pathname, "/proc/net/arp") == 0) {
            create_fake_arp_file();
            if (g_fake_arp_tmpfile[0]) {
                return orig_open(g_fake_arp_tmpfile, O_RDONLY, 0);
            }
        }
        // /proc/self/maps -> filtered
        if (strstr(pathname, "/proc/") && strstr(pathname, "/maps")) {
            create_fake_maps_file(pathname);
            if (g_fake_maps_tmpfile[0]) {
                return orig_open(g_fake_maps_tmpfile, O_RDONLY, 0);
            }
        }
        // /proc/mounts, /proc/self/mountinfo -> filter
        if (strcmp(pathname, "/proc/mounts") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/mountinfo"))) {
            // For mounts, we reuse maps filter logic
            create_fake_maps_file(pathname);
            if (g_fake_maps_tmpfile[0]) {
                return orig_open(g_fake_maps_tmpfile, O_RDONLY, 0);
            }
        }
    }

    if (flags & O_CREAT) {
        return orig_open(pathname, flags, mode);
    }
    return orig_open(pathname, flags);
}

static int hook_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    if (pathname) {
        if (is_root_path(pathname)) {
            errno = ENOENT;
            return -1;
        }
        if (is_mac_path(pathname)) {
            create_fake_mac_file();
            if (g_fake_mac_tmpfile[0]) {
                return orig_openat(AT_FDCWD, g_fake_mac_tmpfile, O_RDONLY, 0);
            }
        }
        if (strcmp(pathname, "/proc/net/arp") == 0) {
            create_fake_arp_file();
            if (g_fake_arp_tmpfile[0]) {
                return orig_openat(AT_FDCWD, g_fake_arp_tmpfile, O_RDONLY, 0);
            }
        }
        if (strstr(pathname, "/proc/") && (strstr(pathname, "/maps") || strstr(pathname, "/mountinfo"))) {
            create_fake_maps_file(pathname);
            if (g_fake_maps_tmpfile[0]) {
                return orig_openat(AT_FDCWD, g_fake_maps_tmpfile, O_RDONLY, 0);
            }
        }
        if (strcmp(pathname, "/proc/mounts") == 0) {
            create_fake_maps_file(pathname);
            if (g_fake_maps_tmpfile[0]) {
                return orig_openat(AT_FDCWD, g_fake_maps_tmpfile, O_RDONLY, 0);
            }
        }
    }

    if (flags & O_CREAT) {
        return orig_openat(dirfd, pathname, flags, mode);
    }
    return orig_openat(dirfd, pathname, flags);
}

static int hook_access(const char *pathname, int mode) {
    if (pathname && is_root_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(pathname, mode);
}

static int hook_stat(const char *pathname, struct stat *buf) {
    if (pathname && is_root_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(pathname, buf);
}

static int hook_lstat(const char *pathname, struct stat *buf) {
    if (pathname && is_root_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(pathname, buf);
}

static FILE *hook_fopen(const char *pathname, const char *mode) {
    if (pathname) {
        if (is_root_path(pathname)) {
            errno = ENOENT;
            return NULL;
        }
        if (is_mac_path(pathname)) {
            create_fake_mac_file();
            if (g_fake_mac_tmpfile[0]) {
                return orig_fopen(g_fake_mac_tmpfile, "r");
            }
        }
        if (strcmp(pathname, "/proc/net/arp") == 0) {
            create_fake_arp_file();
            if (g_fake_arp_tmpfile[0]) {
                return orig_fopen(g_fake_arp_tmpfile, "r");
            }
        }
        if (strstr(pathname, "/proc/") && (strstr(pathname, "/maps") || strstr(pathname, "/mountinfo"))) {
            create_fake_maps_file(pathname);
            if (g_fake_maps_tmpfile[0]) {
                return orig_fopen(g_fake_maps_tmpfile, "r");
            }
        }
        if (strcmp(pathname, "/proc/mounts") == 0) {
            create_fake_maps_file(pathname);
            if (g_fake_maps_tmpfile[0]) {
                return orig_fopen(g_fake_maps_tmpfile, "r");
            }
        }
    }
    return orig_fopen(pathname, mode);
}

static int hook_ioctl(int fd, int request, ...) {
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);

    int ret = orig_ioctl(fd, request, arg);

    // SIOCGIFHWADDR - get hardware (MAC) address
    if (ret == 0 && request == SIOCGIFHWADDR && arg) {
        struct ifreq *ifr = (struct ifreq *)arg;
        // Only spoof for wlan0, eth0, or similar
        if (strcmp(ifr->ifr_name, "wlan0") == 0 ||
            strcmp(ifr->ifr_name, "eth0") == 0 ||
            strstr(ifr->ifr_name, "wlan") != NULL) {
            memcpy(ifr->ifr_hwaddr.sa_data, g_fake_mac_bytes, 6);
            LOGD("ioctl SIOCGIFHWADDR spoofed for %s", ifr->ifr_name);
        }
    }

    // SIOCGIFADDR - get IP address
    if (ret == 0 && request == SIOCGIFADDR && arg) {
        struct ifreq *ifr = (struct ifreq *)arg;
        if (strcmp(ifr->ifr_name, "wlan0") == 0 || strcmp(ifr->ifr_name, "eth0") == 0) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ifr->ifr_addr;
            inet_pton(AF_INET, g_fake_ip, &sin->sin_addr);
        }
    }

    return ret;
}

static int hook___system_property_get(const char *name, char *value) {
    int ret = orig___system_property_get(name, value);

    if (name) {
        if (strcmp(name, "ro.build.tags") == 0) {
            strcpy(value, "release-keys");
        } else if (strcmp(name, "ro.debuggable") == 0) {
            strcpy(value, "0");
        } else if (strcmp(name, "ro.secure") == 0) {
            strcpy(value, "1");
        } else if (strcmp(name, "ro.build.selinux") == 0) {
            strcpy(value, "1");
        } else if (strcmp(name, "ro.build.type") == 0) {
            strcpy(value, "user");
        } else if (strcmp(name, "init.svc.adbd") == 0) {
            strcpy(value, "stopped");
        } else if (strcmp(name, "wifi.interface") == 0) {
            strcpy(value, "wlan0");
        } else if (strstr(name, "magisk") || strstr(name, "supersu")) {
            value[0] = '\0';
            ret = 0;
        }
    }

    return ret;
}

static FILE *hook_popen(const char *command, const char *type) {
    if (command) {
        // Block root detection commands
        if (strstr(command, "su") || strstr(command, "which su") ||
            strstr(command, "magisk") || strstr(command, "busybox")) {
            errno = EACCES;
            return NULL;
        }
        // Block MAC leak commands
        if (strstr(command, "ip link") || strstr(command, "ip addr") ||
            strstr(command, "ifconfig") || strstr(command, "netcfg") ||
            (strstr(command, "cat") && strstr(command, "/sys/class/net"))) {
            errno = EACCES;
            return NULL;
        }
    }
    return orig_popen(command, type);
}

static ssize_t hook_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    ssize_t ret = orig_readlinkat(dirfd, pathname, buf, bufsiz);
    // Filter out xposed/magisk from readlink results
    if (ret > 0 && buf) {
        char tmp[512] = {0};
        size_t len = (ret < 511) ? ret : 511;
        memcpy(tmp, buf, len);
        if (strstr(tmp, "magisk") || strstr(tmp, "xposed") ||
            strstr(tmp, "lsposed") || strstr(tmp, "edxposed")) {
            errno = ENOENT;
            return -1;
        }
    }
    return ret;
}

// ===================== Parse MAC string to bytes =====================
static void parse_mac_bytes(const char *mac_str, unsigned char *out) {
    if (!mac_str || !out) return;
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
}

// ===================== JNI interface =====================
JNIEXPORT void JNICALL
Java_com_fakespoof_wifispoof_NativeHook_nativeInit(JNIEnv *env, jclass clazz,
    jstring mac, jstring ip, jstring gateway, jstring ssid) {

    // Get config from Java
    const char *mac_str = (*env)->GetStringUTFChars(env, mac, NULL);
    const char *ip_str = (*env)->GetStringUTFChars(env, ip, NULL);
    const char *gw_str = (*env)->GetStringUTFChars(env, gateway, NULL);
    const char *ssid_str = (*env)->GetStringUTFChars(env, ssid, NULL);

    strncpy(g_fake_mac, mac_str, sizeof(g_fake_mac) - 1);
    strncpy(g_fake_ip, ip_str, sizeof(g_fake_ip) - 1);
    strncpy(g_fake_gateway, gw_str, sizeof(g_fake_gateway) - 1);
    strncpy(g_fake_ssid, ssid_str, sizeof(g_fake_ssid) - 1);
    parse_mac_bytes(mac_str, g_fake_mac_bytes);

    (*env)->ReleaseStringUTFChars(env, mac, mac_str);
    (*env)->ReleaseStringUTFChars(env, ip, ip_str);
    (*env)->ReleaseStringUTFChars(env, gateway, gw_str);
    (*env)->ReleaseStringUTFChars(env, ssid, ssid_str);

    LOGI("Native hook init: MAC=%s IP=%s GW=%s SSID=%s", g_fake_mac, g_fake_ip, g_fake_gateway, g_fake_ssid);

    // Register PLT hooks
    plt_hook_register("open", (void *)hook_open, (void **)&orig_open);
    plt_hook_register("openat", (void *)hook_openat, (void **)&orig_openat);
    plt_hook_register("access", (void *)hook_access, (void **)&orig_access);
    plt_hook_register("stat", (void *)hook_stat, (void **)&orig_stat);
    plt_hook_register("lstat", (void *)hook_lstat, (void **)&orig_lstat);
    plt_hook_register("fopen", (void *)hook_fopen, (void **)&orig_fopen);
    plt_hook_register("ioctl", (void *)hook_ioctl, (void **)&orig_ioctl);
    plt_hook_register("__system_property_get", (void *)hook___system_property_get, (void **)&orig___system_property_get);
    plt_hook_register("popen", (void *)hook_popen, (void **)&orig_popen);
    plt_hook_register("readlinkat", (void *)hook_readlinkat, (void **)&orig_readlinkat);

    // Apply hooks to all loaded libraries
    int result = plt_hook_commit();
    LOGI("PLT hook commit result: %d", result);
}

// Called when new libraries are loaded (optional re-hook)
JNIEXPORT void JNICALL
Java_com_fakespoof_wifispoof_NativeHook_nativeRefresh(JNIEnv *env, jclass clazz) {
    plt_hook_commit();
}

// Cleanup temp files on unload
__attribute__((destructor))
static void cleanup() {
    if (g_fake_mac_tmpfile[0]) unlink(g_fake_mac_tmpfile);
    if (g_fake_arp_tmpfile[0]) unlink(g_fake_arp_tmpfile);
    if (g_fake_maps_tmpfile[0]) unlink(g_fake_maps_tmpfile);
}
