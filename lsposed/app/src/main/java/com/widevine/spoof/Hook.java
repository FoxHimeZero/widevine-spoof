package com.widevine.spoof;

import android.media.MediaDrm;
import android.util.Log;
import java.io.FileInputStream;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Hook implements IXposedHookLoadPackage {

    private static final String TAG = "WidevineSpoof";
    private static final String ID_FILE = "/data/adb/widevine-spoof/id";
    private static byte[] sFakeId = null;

    private static byte[] loadFakeId() {
        if (sFakeId != null) return sFakeId;
        try (FileInputStream fis = new FileInputStream(ID_FILE)) {
            byte[] data = new byte[16];
            if (fis.read(data) == 16) {
                sFakeId = data;
                Log.i(TAG, "Java 层已加载伪造 ID");
            }
        } catch (Exception e) {
            Log.e(TAG, "加载 ID 失败: " + e.getMessage());
        }
        return sFakeId;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> clazz = Class.forName("android.media.MediaDrm");

            XposedBridge.hookAllMethods(clazz, "getPropertyByteArray",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String prop = (String) param.args[0];
                        if (MediaDrm.PROPERTY_DEVICE_UNIQUE_ID.equals(prop)) {
                            byte[] fakeId = loadFakeId();
                            if (fakeId != null) {
                                param.setResult(fakeId.clone());
                                Log.d(TAG, "Java 层已替换 deviceUniqueId");
                            }
                        }
                    }
                });

            Log.i(TAG, "Java 层 Hook 安装成功");
        } catch (Throwable t) {
            Log.e(TAG, "Hook 失败: " + t.getMessage());
        }
    }
}
