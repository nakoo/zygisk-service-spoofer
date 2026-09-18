#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cctype>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>

#if __has_include(<sys/sysmacros.h>)
#include <sys/sysmacros.h>
#endif

#include <android/log.h>

#include "zygisk.hpp"
#include "dex_bytes.h"

#ifndef makedev
#define makedev(maj, min) ((dev_t)(((maj) << 8) | (min)))
#endif

#define LOG_TAG "ZygiskServiceSpoofer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#if defined(__aarch64__)
#define MEMFD_CREATE_SYSCALL 279
#define OPENAT_SYSCALL 56
#elif defined(__arm__)
#define MEMFD_CREATE_SYSCALL 385
#define OPENAT_SYSCALL 322
#else
#define MEMFD_CREATE_SYSCALL 0
#define OPENAT_SYSCALL 0
#endif

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode) {
#if OPENAT_SYSCALL != 0
    return static_cast<int>(syscall(OPENAT_SYSCALL, dirfd, path, flags, mode));
#else
    (void) dirfd;
    (void) path;
    (void) flags;
    (void) mode;
    errno = ENOSYS;
    return -1;
#endif
}

static std::string read_all_fd(int fd) {
    std::string out;
    char buf[4096];

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        out.append(buf, static_cast<size_t>(n));
    }

    return out;
}

static std::string trim_string(const std::string &input) {
    size_t start = 0;
    size_t end = input.size();

    while (start < end && std::isspace(static_cast<unsigned char>(input[start]))) {
        start++;
    }

    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
        end--;
    }

    return input.substr(start, end - start);
}

// ---------------------------------------------------------------------------
// Text-file based target selection
//
// File location:
//   /data/adb/modules/zygisk_service_spoofer/targets.txt
//
// Supported lines:
//   *
//   com.example.app
//   com.example.*
//
// Lines starting with '#' are ignored.
//
// If targets.txt does not exist, the module defaults to:
//   com.reveny.nativecheck
//
// If targets.txt exists but is empty, the module targets nothing.
// ---------------------------------------------------------------------------

static std::vector<std::string> load_target_list(Api *api, bool *config_exists) {
    std::vector<std::string> targets;

    if (config_exists != nullptr) {
        *config_exists = false;
    }

    if (api == nullptr) {
        return targets;
    }

    int module_dir = api->getModuleDir();
    if (module_dir < 0) {
        LOGE("config: getModuleDir failed");
        return targets;
    }

    int fd = openat(module_dir, "targets.txt", O_RDONLY | O_CLOEXEC);
    close(module_dir);

    if (fd < 0) {
        return targets;
    }

    if (config_exists != nullptr) {
        *config_exists = true;
    }

    std::string content = read_all_fd(fd);
    close(fd);

    size_t start = 0;

    while (start < content.size()) {
        size_t newline = content.find('\n', start);
        std::string line;

        if (newline == std::string::npos) {
            line = content.substr(start);
        } else {
            line = content.substr(start, newline - start);
        }

        line = trim_string(line);

        if (!line.empty() && line[0] != '#') {
            targets.push_back(line);
        }

        if (newline == std::string::npos) break;
        start = newline + 1;
    }

    return targets;
}

static bool process_matches_target(const char *process, std::string target) {
    if (process == nullptr) return false;

    target = trim_string(target);
    if (target.empty()) return false;

    if (target == "*") {
        return true;
    }

    bool prefix_wildcard = false;

    if (target.back() == '*') {
        prefix_wildcard = true;
        target.pop_back();
        target = trim_string(target);
    }

    if (target.empty()) {
        return prefix_wildcard;
    }

    if (strncmp(process, target.c_str(), target.size()) != 0) {
        return false;
    }

    if (prefix_wildcard) {
        return true;
    }

    char next = process[target.size()];

    // Match:
    //   com.example.app
    //   com.example.app:service
    //   com.example.app_zygote-like child zygote names
    return next == '\0' || next == ':' || next == '_';
}

// ---------------------------------------------------------------------------
// Native hooks: /proc/self/maps sanitization and property hiding
// ---------------------------------------------------------------------------

using openat_t   = int (*)(int, const char *, int, mode_t);
using openat_2_t = int (*)(int, const char *, int);
using open_t     = int (*)(const char *, int, mode_t);
using open_2_t   = int (*)(const char *, int);
using prop_get_t = int (*)(const char *, char *);

static openat_t   orig_openat   = nullptr;
static openat_2_t orig_openat_2 = nullptr;
static open_t     orig_open     = nullptr;
static open_2_t   orig_open_2   = nullptr;
static prop_get_t orig_prop_get = nullptr;

static bool is_maps_path(const char *path) {
    if (path == nullptr) return false;

    if (strcmp(path, "/proc/self/maps") == 0) return true;
    if (strcmp(path, "proc/self/maps") == 0) return true;

    return false;
}

static bool should_remove_maps_line(const std::string &line) {
    // Hide bare unnamed anonymous mappings:
    //
    // 6e63b6a000-6e63ba7000 r-xp 00000000 00:00 0 [anon:]
    if (line.find("[anon:]") != std::string::npos) {
        return true;
    }

    // Hide in-memory DEX-style mappings if present.
    if (line.find("[anon:dalvik-classes") != std::string::npos) {
        return true;
    }

    // Hide this module itself, because native PLT hooks require the module
    // library to remain mapped.
    if (line.find("libservice_spoofer") != std::string::npos) {
        return true;
    }
    if (line.find("/data/adb/modules/") != std::string::npos) {
        return true;
    }

    return false;
}

static std::string sanitize_maps(const std::string &input) {
    std::string output;
    size_t start = 0;

    while (start < input.size()) {
        size_t newline = input.find('\n', start);
        std::string line;

        if (newline == std::string::npos) {
            line = input.substr(start);
        } else {
            line = input.substr(start, newline - start + 1);
        }

        if (!should_remove_maps_line(line)) {
            output += line;
        }

        if (newline == std::string::npos) break;
        start = newline + 1;
    }

    return output;
}

static int create_sanitized_fd(const std::string &content, int flags) {
#if MEMFD_CREATE_SYSCALL != 0
    int fd = static_cast<int>(syscall(MEMFD_CREATE_SYSCALL, "maps", 0));
    if (fd < 0) return -1;

    size_t offset = 0;
    while (offset < content.size()) {
        ssize_t written = write(fd, content.data() + offset, content.size() - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        offset += static_cast<size_t>(written);
    }

    if (offset != content.size()) {
        close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);

    if (flags & O_CLOEXEC) {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }

    return fd;
#else
    (void) content;
    (void) flags;
    return -1;
#endif
}

static int sanitized_maps_open(int dirfd, const char *path, int flags) {
    int real_fd = -1;

    if (orig_openat != nullptr) {
        real_fd = orig_openat(dirfd, path, O_RDONLY, 0);
    } else {
        real_fd = raw_openat(dirfd, path, O_RDONLY, 0);
    }

    if (real_fd < 0) {
        return real_fd;
    }

    std::string content = read_all_fd(real_fd);

    if (content.empty()) {
        lseek(real_fd, 0, SEEK_SET);
        if (flags & O_CLOEXEC) {
            fcntl(real_fd, F_SETFD, FD_CLOEXEC);
        }
        return real_fd;
    }

    close(real_fd);

    std::string filtered = sanitize_maps(content);
    int sanitized_fd = create_sanitized_fd(filtered, flags);

    if (sanitized_fd >= 0) {
        return sanitized_fd;
    }

    // Fallback: return the real maps file if memfd creation failed.
    if (orig_openat != nullptr) {
        return orig_openat(dirfd, path, flags, 0);
    }

    return raw_openat(dirfd, path, flags, 0);
}

static int my_openat(int dirfd, const char *path, int flags, mode_t mode) {
    if (is_maps_path(path)) {
        return sanitized_maps_open(dirfd, path, flags);
    }

    if (orig_openat != nullptr) {
        return orig_openat(dirfd, path, flags, mode);
    }

    return raw_openat(dirfd, path, flags, mode);
}

static int my_openat_2(int dirfd, const char *path, int flags) {
    if (is_maps_path(path)) {
        return sanitized_maps_open(dirfd, path, flags);
    }

    if (orig_openat_2 != nullptr) {
        return orig_openat_2(dirfd, path, flags);
    }

    if (orig_openat != nullptr) {
        return orig_openat(dirfd, path, flags, 0);
    }

    return raw_openat(dirfd, path, flags, 0);
}

static int my_open(const char *path, int flags, mode_t mode) {
    if (is_maps_path(path)) {
        return sanitized_maps_open(AT_FDCWD, path, flags);
    }

    if (orig_open != nullptr) {
        return orig_open(path, flags, mode);
    }

    return raw_openat(AT_FDCWD, path, flags, mode);
}

static int my_open_2(const char *path, int flags) {
    if (is_maps_path(path)) {
        return sanitized_maps_open(AT_FDCWD, path, flags);
    }

    if (orig_open_2 != nullptr) {
        return orig_open_2(path, flags);
    }

    if (orig_open != nullptr) {
        return orig_open(path, flags, 0);
    }

    return raw_openat(AT_FDCWD, path, flags, 0);
}

static int my_system_property_get(const char *name, char *value) {
    if (name != nullptr && value != nullptr && strcmp(name, "init.svc.adb_root") == 0) {
        value[0] = '\0';
        return 0;
    }

    if (orig_prop_get != nullptr) {
        return orig_prop_get(name, value);
    }

    return 0;
}

static void install_native_hooks(Api *api) {
    static bool installed = false;
    if (installed || api == nullptr) return;
    installed = true;

    // Use 0, 0 to hook the symbols in ALL currently loaded ELFs in the process.
    // libc.so exports these functions, so they are not in its own PLT.
    dev_t dev = 0;
    ino_t inode = 0;

    api->pltHookRegister(dev, inode, "openat",
                         reinterpret_cast<void *>(my_openat),
                         reinterpret_cast<void **>(&orig_openat));

    api->pltHookRegister(dev, inode, "__openat_2",
                         reinterpret_cast<void *>(my_openat_2),
                         reinterpret_cast<void **>(&orig_openat_2));

    api->pltHookRegister(dev, inode, "open",
                         reinterpret_cast<void *>(my_open),
                         reinterpret_cast<void **>(&orig_open));

    api->pltHookRegister(dev, inode, "__open_2",
                         reinterpret_cast<void *>(my_open_2),
                         reinterpret_cast<void **>(&orig_open_2));

    api->pltHookRegister(dev, inode, "__system_property_get",
                         reinterpret_cast<void *>(my_system_property_get),
                         reinterpret_cast<void **>(&orig_prop_get));

    if (!api->pltHookCommit()) {
        LOGE("native hooks: pltHookCommit failed");
    } else {
        LOGI("native hooks: installed");
    }
}

// ---------------------------------------------------------------------------
// Original Java hook installation
// ---------------------------------------------------------------------------

static void exempt_all_hidden_apis(JNIEnv* env) {
    jclass vm_runtime_cls = env->FindClass("dalvik/system/VMRuntime");
    if (!vm_runtime_cls) return;

    jmethodID get_runtime_mid = env->GetStaticMethodID(vm_runtime_cls, "getRuntime", "()Ldalvik/system/VMRuntime;");
    if (!get_runtime_mid) {
        env->DeleteLocalRef(vm_runtime_cls);
        return;
    }

    jobject runtime_obj = env->CallStaticObjectMethod(vm_runtime_cls, get_runtime_mid);
    if (!runtime_obj) {
        env->DeleteLocalRef(vm_runtime_cls);
        return;
    }

    jmethodID set_exemptions_mid = env->GetMethodID(vm_runtime_cls, "setHiddenApiExemptions", "([Ljava/lang/String;)V");
    if (set_exemptions_mid) {
        jclass string_cls = env->FindClass("java/lang/String");
        jstring exemption_pattern = env->NewStringUTF("L");
        jobjectArray exemptions = env->NewObjectArray(1, string_cls, exemption_pattern);

        env->CallVoidMethod(runtime_obj, set_exemptions_mid, exemptions);

        env->DeleteLocalRef(exemptions);
        env->DeleteLocalRef(exemption_pattern);
        env->DeleteLocalRef(string_cls);
    }

    env->DeleteLocalRef(runtime_obj);
    env->DeleteLocalRef(vm_runtime_cls);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static void install_service_hook(JNIEnv* env) {
    exempt_all_hidden_apis(env);

    jclass byte_buffer_cls = env->FindClass("java/nio/ByteBuffer");
    if (!byte_buffer_cls) return;

    jmethodID wrap_mid = env->GetStaticMethodID(byte_buffer_cls, "wrap", "([B)Ljava/nio/ByteBuffer;");
    jbyteArray dex_byte_array = env->NewByteArray(classes_dex_len);
    env->SetByteArrayRegion(dex_byte_array, 0, classes_dex_len, reinterpret_cast<const jbyte*>(classes_dex));
    jobject buffer_obj = env->CallStaticObjectMethod(byte_buffer_cls, wrap_mid, dex_byte_array);

    jclass class_loader_cls = env->FindClass("java/lang/ClassLoader");
    jmethodID get_system_loader_mid = env->GetStaticMethodID(class_loader_cls, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject system_loader = env->CallStaticObjectMethod(class_loader_cls, get_system_loader_mid);

    jclass in_memory_loader_cls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID loader_ctor = env->GetMethodID(in_memory_loader_cls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject loader_obj = env->NewObject(in_memory_loader_cls, loader_ctor, buffer_obj, system_loader);

    jmethodID load_class_mid = env->GetMethodID(in_memory_loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring class_name = env->NewStringUTF("com.android.internal.util.ServiceHook");
    jclass hook_cls = reinterpret_cast<jclass>(env->CallObjectMethod(loader_obj, load_class_mid, class_name));

    if (hook_cls) {
        jmethodID install_mid = env->GetStaticMethodID(hook_cls, "install", "()V");
        if (install_mid) {
            env->CallStaticVoidMethod(hook_cls, install_mid);
        }
        env->DeleteLocalRef(hook_cls);
    }

    env->DeleteLocalRef(class_name);
    env->DeleteLocalRef(loader_obj);
    env->DeleteLocalRef(in_memory_loader_cls);
    env->DeleteLocalRef(system_loader);
    env->DeleteLocalRef(class_loader_cls);
    env->DeleteLocalRef(buffer_obj);
    env->DeleteLocalRef(dex_byte_array);
    env->DeleteLocalRef(byte_buffer_cls);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

class ServiceHiderModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        bool config_exists = false;
        std::vector<std::string> targets = load_target_list(api, &config_exists);

        // If no targets.txt exists, use a safe default target.
        // If targets.txt exists but is empty, the module targets nothing.
        if (!config_exists) {
            targets.push_back("com.reveny.nativecheck");
        }

        bool targeted = false;
        const char *process = nullptr;

        if (args->nice_name) {
            process = env->GetStringUTFChars(args->nice_name, nullptr);
        }

        for (const std::string &target : targets) {
            if (target == "*" && args->uid >= 10000) {
                targeted = true;
                break;
            }

            if (process != nullptr && process_matches_target(process, target)) {
                targeted = true;
                break;
            }
        }

        if (process != nullptr) {
            if (targeted) {
                LOGI("config: targeting process: %s", process);
            }
            env->ReleaseStringUTFChars(args->nice_name, process);
        }

        if (targeted) {
            is_target = true;

            // Install native PLT hooks before app code runs.
            install_native_hooks(api);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!is_target) return;

        install_service_hook(env);

        // Automatically dlclose and unmap this module's shared library from memory
        // Disabled because native PLT hooks must remain mapped in memory.
        // api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;
    bool is_target{false};
};

REGISTER_ZYGISK_MODULE(ServiceHiderModule)
