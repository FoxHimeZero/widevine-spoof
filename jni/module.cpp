#include <sys/types.h>
#include "zygisk.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <media/NdkMediaDrm.h>   // 提供 AMediaDrmByteArray 等类型

#include "Dobby.h"               // Dobby 头文件

#define LOG_TAG "WidevineSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using namespace zygisk;

static const char *kTargetProcess = "android.hardware.drm-service.widevine";
static const char *kIdFile = "/data/local/tmp/widevine-spoof/id";
static std::vector<uint8_t> g_fakeId;

// 原始函数指针（Dobby 会填充）
static media_status_t (*orig_getPropertyByteArray)(
    AMediaDrm*, const char*, AMediaDrmByteArray*) = nullptr;

// 加载伪造 ID
static bool loadFakeId() {
    std::ifstream f(kIdFile, std::ios::binary);
    if (!f) { LOGE("无法打开 ID 文件"); return false; }
    g_fakeId.assign(std::istreambuf_iterator<char>(f),
                    std::istreambuf_iterator<char>());
    if (g_fakeId.size() != 16) {
        LOGE("ID 大小错误: %zu", g_fakeId.size());
        return false;
    }
    LOGI("ID 已加载: %zu 字节", g_fakeId.size());
    return true;
}

// Hook 函数
static media_status_t hook_getPropertyByteArray(
    AMediaDrm *drm, const char *propertyName,
    AMediaDrmByteArray *propertyValue) {

    media_status_t ret = orig_getPropertyByteArray(drm, propertyName, propertyValue);

    if (propertyName && strstr(propertyName, "deviceUniqueId") &&
        propertyValue && propertyValue->ptr && propertyValue->length > 0 &&
        !g_fakeId.empty()) {

        // 替换内存中的值
        size_t addr = (size_t)propertyValue->ptr;
        size_t pg = sysconf(_SC_PAGESIZE);
        size_t aAddr = addr & ~(pg - 1);
        size_t aSize = ((addr + propertyValue->length) - aAddr + pg - 1) & ~(pg - 1);

        if (mprotect((void*)aAddr, aSize,
                     PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            memcpy((void*)propertyValue->ptr, g_fakeId.data(), g_fakeId.size());
            LOGI("Dobby Hook 成功替换 deviceUniqueId");
        } else {
            LOGE("mprotect 失败: %s", strerror(errno));
        }
    }
    return ret;
}

class SpoofModule : public ModuleBase {
    JNIEnv *g_env = nullptr;
public:
    void onLoad(Api *api, JNIEnv *env) override {
        g_env = env;
        LOGI("Zygisk 模块已加载");
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args->nice_name) return;
        const char *n = g_env->GetStringUTFChars(args->nice_name, nullptr);
        if (!n) return;
        bool t = (strcmp(n, kTargetProcess) == 0);
        g_env->ReleaseStringUTFChars(args->nice_name, n);
        if (t) loadFakeId();
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (g_fakeId.empty()) { LOGE("ID 为空，跳过 Hook"); return; }

        void *h = dlopen("libmediadrm.so", RTLD_NOW);
        if (!h) { LOGE("无法加载 libmediadrm.so"); return; }

        void *target = dlsym(h, "AMediaDrm_getPropertyByteArray");
        if (!target) { LOGE("未找到目标函数"); dlclose(h); return; }

        LOGI("找到目标函数: %p", target);

        // 使用 Dobby 进行 inline hook
        int ret = DobbyHook(target,
                            (void*)hook_getPropertyByteArray,
                            (void**)&orig_getPropertyByteArray);

        if (ret == 0) {
            LOGI("Dobby Hook 安装成功");
        } else {
            LOGE("DobbyHook 失败: %d", ret);
        }
    }
};

REGISTER_ZYGISK_MODULE(SpoofModule)
