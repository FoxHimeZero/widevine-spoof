#include "zygisk.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>

#define LOG_TAG "WidevineSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using namespace zygisk;

static const char *kTargetProcess = "android.hardware.drm-service.widevine";
static const char *kIdFile = "/data/adb/widevine-spoof/id";
static std::vector<uint8_t> g_fakeId;

static bool loadFakeId() {
    std::ifstream f(kIdFile, std::ios::binary);
    if (!f) { LOGE("无法打开 ID 文件"); return false; }
    g_fakeId.assign(std::istreambuf_iterator<char>(f),
                    std::istreambuf_iterator<char>());
    if (g_fakeId.size() != 16) { LOGE("ID 大小错误"); return false; }
    LOGI("ID 已加载");
    return true;
}

static media_status_t (*orig_getProp)(AMediaDrm*, const char*, AMediaDrmByteArray*) = nullptr;

static media_status_t hook_getProp(AMediaDrm *drm, const char *name, AMediaDrmByteArray *val) {
    media_status_t ret = orig_getProp(drm, name, val);
    if (name && strstr(name, "deviceUniqueId") && val && val->ptr && val->length > 0 && !g_fakeId.empty()) {
        size_t addr = (size_t)val->ptr;
        size_t pg = sysconf(_SC_PAGESIZE);
        size_t aAddr = addr & ~(pg - 1);
        size_t aSize = ((addr + val->length) - aAddr + pg - 1) & ~(pg - 1);
        if (mprotect((void*)aAddr, aSize, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            memcpy((void*)val->ptr, g_fakeId.data(), g_fakeId.size());
            LOGI("已替换 deviceUniqueId");
        }
    }
    return ret;
}

class SpoofModule : public ModuleBase {
    JNIEnv *g_env = nullptr;
public:
    void onLoad(Api *api, JNIEnv *env) override { g_env = env; }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args->nice_name) return;
        const char *n = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!n) return;
        bool t = (strcmp(n, kTargetProcess) == 0);
        g_env->ReleaseStringUTFChars(args->nice_name, n);
        if (t) loadFakeId();
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (g_fakeId.empty()) return;
        void *h = dlopen("libmediadrm.so", RTLD_NOW);
        if (!h) return;
        void *target = dlsym(h, "AMediaDrm_getPropertyByteArray");
        if (!target) { dlclose(h); return; }
        extern int DobbyHook(void*, void*, void**);
        DobbyHook(target, (void*)hook_getProp, (void**)&orig_getProp);
    }
};

REGISTER_ZYGISK_MODULE(SpoofModule)
