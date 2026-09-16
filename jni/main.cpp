#include <jni.h>
#include <string>
#include <vector>
#include <cstring>
#include <atomic>
#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <sys/prctl.h>
#include <android/log.h>
#include "zygisk.hpp"
#include "dex_bytes.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

#define LOG_TAG "SpooferHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

static std::atomic<bool> is_target_app{false};

static void sanitize_executable_maps() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps: %d (%s)", errno, strerror(errno));
        return;
    }

    char line[512];
    struct MapRange {
        uintptr_t start;
        uintptr_t end;
    };
    std::vector<MapRange> targets;

    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start = 0, end = 0;
        char perms[5] = {0};
        int path_offset = 0;
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %n", &start, &end, perms, &path_offset) >= 3) {
            if (perms[2] == 'x') {
                std::string path = (path_offset > 0 && path_offset < (int)strlen(line)) ? (line + path_offset) : "";
                while (!path.empty() && (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) {
                    path.pop_back();
                }
                if (path.find("<fault>") != std::string::npos || path.find("fault") != std::string::npos) {
                    targets.push_back({start, end});
                }
            }
        }
    }
    fclose(fp);

    LOGI("Found %zu target mapping(s) matching 'fault'", targets.size());

    for (const auto& target : targets) {
        int ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, target.start, target.end - target.start, "dalvik-jit-code-cache");
        if (ret != 0) {
            LOGE("prctl failed for %p-%p: %d (%s)", (void*)target.start, (void*)target.end, errno, strerror(errno));
        } else {
            LOGI("Successfully renamed VMA %p-%p to dalvik-jit-code-cache", (void*)target.start, (void*)target.end);
        }
    }
}

static void exempt_all_hidden_apis(JNIEnv* env) {
    jclass vm_runtime_cls = env->FindClass("dalvik/system/VMRuntime");
    if (!vm_runtime_cls) return;
    jmethodID get_runtime_mid = env->GetStaticMethodID(vm_runtime_cls, "getRuntime", "()Ldalvik/system/VMRuntime;");
    if (!get_runtime_mid) { env->DeleteLocalRef(vm_runtime_cls); return; }
    jobject runtime_obj = env->CallStaticObjectMethod(vm_runtime_cls, get_runtime_mid);
    if (!runtime_obj) { env->DeleteLocalRef(vm_runtime_cls); return; }
    jmethodID set_exemptions_mid = env->GetMethodID(vm_runtime_cls, "setHiddenApiExemptions", "([Ljava/lang/String;)V");
    if (set_exemptions_mid) {
        jclass string_cls = env->FindClass("java/lang/String");
        jobjectArray exemptions = env->NewObjectArray(1, string_cls, env->NewStringUTF("L"));
        env->CallVoidMethod(runtime_obj, set_exemptions_mid, exemptions);
        env->DeleteLocalRef(exemptions);
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
            LOGI("ServiceHook.install() invoked successfully");
        }
    }

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

class ServiceHiderModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGI("onLoad called in pid %d", getpid());
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        LOGI("preAppSpecialize: nice_name=%s, is_child_zygote=%d",
             process ? process : "null",
             (args->is_child_zygote && *args->is_child_zygote) ? 1 : 0);

        if (args->is_child_zygote && *args->is_child_zygote) {
            if (process) env->ReleaseStringUTFChars(args->nice_name, process);
            return;
        }

        if (process) {
            if (strstr(process, "_zygote") == nullptr &&
                strncmp(process, "com.eltavine.duckdetector", 25) == 0) {
                is_target_app.store(true, std::memory_order_relaxed);
                LOGI("Target app matched: %s", process);
            }
            env->ReleaseStringUTFChars(args->nice_name, process);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        LOGI("postAppSpecialize: is_target_app=%d", is_target_app.load() ? 1 : 0);
        if (!is_target_app.load(std::memory_order_relaxed)) return;
        sanitize_executable_maps();
        install_service_hook(env);
    }

private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(ServiceHiderModule)
