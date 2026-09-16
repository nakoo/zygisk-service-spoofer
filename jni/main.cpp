#include <jni.h>
#include <string>
#include <cstring>
#include <atomic>
#include "zygisk.hpp"
#include "dex_bytes.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

static std::atomic<bool> is_target_app{false};

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
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process) {
            // Match main app and any helper sub-processes
            if (strncmp(process, "com.eltavine.duckdetector", 25) == 0) {
                is_target_app.store(true, std::memory_order_relaxed);
            }
            env->ReleaseStringUTFChars(args->nice_name, process);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!is_target_app.load(std::memory_order_relaxed)) return;
        install_service_hook(env);
    }

private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(ServiceHiderModule)
