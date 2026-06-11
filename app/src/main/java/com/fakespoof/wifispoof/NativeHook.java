package com.fakespoof.wifispoof;

/**
 * Native hook bridge - loads native library and initializes PLT hooks
 * to intercept libc calls (open, ioctl, stat, access, etc.)
 */
public class NativeHook {

    private static boolean sLoaded = false;

    public static boolean load() {
        if (sLoaded) return true;
        try {
            System.loadLibrary("native_hook");
            sLoaded = true;
            return true;
        } catch (UnsatisfiedLinkError e) {
            return false;
        }
    }

    public static void init(String mac, String ip, String gateway, String ssid) {
        if (!sLoaded) return;
        try {
            nativeInit(mac, ip, gateway, ssid);
        } catch (Throwable t) {
            // ignore
        }
    }

    public static void refresh() {
        if (!sLoaded) return;
        try {
            nativeRefresh();
        } catch (Throwable t) {
            // ignore
        }
    }

    private static native void nativeInit(String mac, String ip, String gateway, String ssid);
    private static native void nativeRefresh();
}
