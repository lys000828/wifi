package com.fakespoof.wifispoof;

import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

public class HookModule implements IXposedHookLoadPackage {
    private static final String TAG = "WifiSpoof";
    private static final String PREF_NAME = "wifi_spoof_config";
    private static final String PKG_SELF = "com.fakespoof.wifispoof";
    private static final String LOG_FILE = "/sdcard/wifispoof_hook.log";

    private String fakeBSSID = "AA:BB:CC:DD:EE:FF";
    private String fakeMAC = "AA:BB:CC:DD:EE:FF";
    private String fakeSSID = "MyHomeWiFi";
    private boolean enabled = true;

    private String fakeIP = "192.168.1.100";
    private String fakeGateway = "192.168.1.1";
    private String fakeNetmask = "255.255.255.0";
    private String fakeDNS1 = "8.8.8.8";
    private String fakeDNS2 = "8.8.4.4";
    private int fakeFrequency = 5180;
    private int fakeLinkSpeed = 72;
    private int fakeRSSI = -45;
    private int fakeNetworkId = 1;

    private static final Set<String> ROOT_PATHS = new HashSet<>(Arrays.asList(
        "/system/app/Superuser.apk", "/system/app/Superuser",
        "/system/xbin/su", "/system/bin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su", "/su/bin", "/su",
        "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
        "/system/bin/magisk", "/system/xbin/magisk",
        "/cache/.disable_magisk", "/dev/.magisk.unblock",
        "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/magisk.apk",
        "/system/bin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
        "/system/xbin/daemonsu", "/system/xbin/busybox",
        "/system/bin/.ext/.su", "/system/usr/we-need-root/",
        "/data/adb/ksu", "/data/adb/ksud", "/data/adb/lspd"
    ));

    private static final Set<String> ROOT_PACKAGES = new HashSet<>(Arrays.asList(
        "com.topjohnwu.magisk", "io.github.vvb2060.magisk", "com.fox2code.mmm",
        "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.thirdparty.superuser", "com.yellowes.su",
        "com.kingroot.kinguser", "com.kingo.root",
        "com.zhiqupk.root.global", "com.smedialink.oneclickroot",
        "com.alephzain.framaroot", "de.robv.android.xposed.installer",
        "org.lsposed.manager", "org.meowcat.edxposed.manager",
        "com.solohsu.android.edxp.manager", "io.github.lsposed.manager",
        "me.weishu.exp", "com.saurik.substrate", "de.robv.android.xposed",
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadd", "com.formyhm.hiderootPremium",
        "com.formyhm.hideroot"
    ));

    private static final String[] SYSTEM_PACKAGES = {
        "android", "com.android.wifi", "com.android.systemui",
        "com.android.settings", "com.android.providers.settings",
        "com.android.providers.media", "com.android.providers.downloads",
        "system_server", "com.android.server", "com.android.phone",
        "com.android.bluetooth", "com.android.nfc",
        "com.android.shell", "com.android.emergency"
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName.equals(PKG_SELF)) return;

        writeLog("=== WifiSpoof Hook ===");
        writeLog("Package: " + lpparam.packageName);

        if (isSystemPackage(lpparam.packageName)) {
            writeLog("SKIP system: " + lpparam.packageName);
            return;
        }

        loadConfig(lpparam.classLoader, lpparam.packageName);
        if (!enabled) {
            writeLog("DISABLED, skip " + lpparam.packageName);
            return;
        }

        writeLog("Config: MAC=" + fakeMAC + " BSSID=" + fakeBSSID + " SSID=" + fakeSSID + " IP=" + fakeIP);

        // Native层hook - 拦截libc调用（open/ioctl/stat/access等）
        initNativeHook(lpparam.classLoader);

        // Java层hook
        hookWifiApi(lpparam.classLoader);
        hookNetworkInterface(lpparam.classLoader);
        hookNetworkLayer(lpparam.classLoader);
        hookScanResults(lpparam.classLoader);
        hookSystemProperties(lpparam.classLoader);
        hookFileSystem(lpparam.classLoader);
        hookCommandExecution(lpparam.classLoader);
        hookRootHiding(lpparam.classLoader);
        hookMacLeaks(lpparam.classLoader);

        writeLog("--- All hooks done ---");
        XposedBridge.log(TAG + ": hooked " + lpparam.packageName);
    }

    // 初始化Native层hook
    private void initNativeHook(ClassLoader cl) {
        try {
            // 尝试从模块APK中加载native库
            String nativeDir = null;
            try {
                android.content.pm.ApplicationInfo ai = null;
                Object at = XposedHelpers.callStaticMethod(
                    Class.forName("android.app.ActivityThread"), "currentActivityThread");
                Object sysCtx = XposedHelpers.callMethod(at, "getSystemContext");
                Object pm = XposedHelpers.callMethod(sysCtx, "getPackageManager");
                ai = (android.content.pm.ApplicationInfo) XposedHelpers.callMethod(pm,
                    "getApplicationInfo", PKG_SELF, 0);
                nativeDir = ai.nativeLibraryDir;
            } catch (Throwable t) {
                // fallback: try common paths
                String[] paths = {
                    "/data/app/~~*/com.fakespoof.wifispoof-*/lib/arm64",
                    "/data/app/com.fakespoof.wifispoof-*/lib/arm64-v8a",
                    "/data/app/com.fakespoof.wifispoof-*/lib/armeabi-v7a"
                };
                for (String p : paths) {
                    File dir = new File(p.replace("*", ""));
                    if (dir.exists()) { nativeDir = dir.getAbsolutePath(); break; }
                }
            }

            if (nativeDir != null) {
                String libPath = nativeDir + "/libnative_hook.so";
                if (new File(libPath).exists()) {
                    System.load(libPath);
                    NativeHook.init(fakeMAC, fakeIP, fakeGateway, fakeSSID);
                    writeLog("OK Native hook loaded from: " + libPath);
                    return;
                }
            }

            // 直接尝试loadLibrary (可能在目标进程的lib路径中)
            if (NativeHook.load()) {
                NativeHook.init(fakeMAC, fakeIP, fakeGateway, fakeSSID);
                writeLog("OK Native hook loaded via loadLibrary");
            } else {
                writeLog("WARN Native hook library not available");
            }
        } catch (Throwable t) {
            writeLog("FAIL Native hook: " + t.getMessage());
            XposedBridge.log(TAG + ": native hook failed: " + t.getMessage());
        }
    }

    private boolean isSystemPackage(String packageName) {
        if (packageName == null) return true;
        for (String sysPkg : SYSTEM_PACKAGES) {
            if (sysPkg.equals(packageName)) return true;
        }
        if (packageName.startsWith("com.android.") && !packageName.equals("com.android.chrome")) {
            return true;
        }
        return false;
    }

    // ====================================================================
    // 1. WiFi API层
    // ====================================================================
    private void hookWifiApi(ClassLoader cl) {
        hook("android.net.wifi.WifiManager", cl, "getConnectionInfo", p -> {
            WifiInfo fake = buildFakeWifiInfo();
            if (fake != null) p.setResult(fake);
        });
        hook("android.net.wifi.WifiInfo", cl, "getBSSID", p -> p.setResult(fakeBSSID));
        hook("android.net.wifi.WifiInfo", cl, "getSSID", p -> p.setResult("\"" + fakeSSID + "\""));
        hook("android.net.wifi.WifiInfo", cl, "getMacAddress", p -> p.setResult(fakeMAC));
        hook("android.net.wifi.WifiInfo", cl, "getNetworkId", p -> p.setResult(fakeNetworkId));
        hook("android.net.wifi.WifiInfo", cl, "getRssi", p -> p.setResult(fakeRSSI));
        hook("android.net.wifi.WifiInfo", cl, "getLinkSpeed", p -> p.setResult(fakeLinkSpeed));
        hook("android.net.wifi.WifiInfo", cl, "getFrequency", p -> p.setResult(fakeFrequency));
        hook("android.net.wifi.WifiInfo", cl, "getIpAddress", p -> p.setResult(ipToInt(fakeIP)));
        hook("android.net.wifi.WifiInfo", cl, "getServerAddress", p -> p.setResult(ipToInt(fakeGateway)));
        hook("android.net.wifi.WifiManager", cl, "isWifiEnabled", p -> p.setResult(true));
        hook("android.net.wifi.WifiManager", cl, "getWifiState", p -> p.setResult(3));
    }

    // ====================================================================
    // 2. NetworkInterface层
    // ====================================================================
    private void hookNetworkInterface(ClassLoader cl) {
        try {
            findAndHookMethod(NetworkInterface.class, "getHardwareAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NetworkInterface ni = (NetworkInterface) param.thisObject;
                    String name = ni.getName();
                    if (name != null && (name.equals("wlan0") || name.equals("eth0") || name.contains("wlan"))) {
                        param.setResult(parseMac(fakeMAC));
                    }
                }
            });
        } catch (Throwable t) { writeLog("FAIL getHardwareAddress: " + t.getMessage()); }

        try {
            findAndHookMethod(NetworkInterface.class, "getByName", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String name = (String) param.args[0];
                    if (name != null && (name.equals("eth0") || name.contains("veth"))) {
                        try { param.setResult(NetworkInterface.getByName("wlan0")); }
                        catch (Exception e) { }
                    }
                }
            });
        } catch (Throwable t) { writeLog("FAIL getByName: " + t.getMessage()); }

        try {
            findAndHookMethod(NetworkInterface.class, "getNetworkInterfaces", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    @SuppressWarnings("unchecked")
                    Enumeration<NetworkInterface> result = (Enumeration<NetworkInterface>) param.getResult();
                    if (result == null) return;
                    List<NetworkInterface> list = new ArrayList<>();
                    boolean hasWlan0 = false;
                    while (result.hasMoreElements()) {
                        NetworkInterface ni = result.nextElement();
                        if ("wlan0".equals(ni.getName())) hasWlan0 = true;
                        list.add(ni);
                    }
                    if (!hasWlan0) {
                        try {
                            NetworkInterface wlan0 = NetworkInterface.getByName("wlan0");
                            if (wlan0 != null) list.add(0, wlan0);
                        } catch (Exception e) { }
                    }
                    param.setResult(java.util.Collections.enumeration(list));
                }
            });
        } catch (Throwable t) { writeLog("FAIL getNetworkInterfaces: " + t.getMessage()); }

        try {
            findAndHookMethod(NetworkInterface.class, "getName", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String name = (String) param.getResult();
                    if (name != null && (name.equals("eth0") || name.contains("veth"))) {
                        param.setResult("wlan0");
                    }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod(NetworkInterface.class, "getDisplayName", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String name = (String) param.getResult();
                    if (name != null && (name.equals("eth0") || name.contains("veth"))) {
                        param.setResult("wlan0");
                    }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod(NetworkInterface.class, "getInetAddresses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NetworkInterface ni = (NetworkInterface) param.thisObject;
                    String name = ni.getName();
                    if (name != null && (name.equals("wlan0") || name.contains("wlan")
                            || name.equals("eth0"))) {
                        try {
                            List<InetAddress> addrs = new ArrayList<>();
                            addrs.add(InetAddress.getByName(fakeIP));
                            param.setResult(java.util.Collections.enumeration(addrs));
                        } catch (Exception e) { }
                    }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod(NetworkInterface.class, "getInterfaceAddresses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NetworkInterface ni = (NetworkInterface) param.thisObject;
                    String name = ni.getName();
                    if (name != null && (name.equals("wlan0") || name.contains("wlan")
                            || name.equals("eth0"))) {
                        try {
                            Class<?> ifAddrClass = Class.forName("java.net.InterfaceAddress");
                            java.lang.reflect.Constructor<?> ctor = ifAddrClass.getDeclaredConstructor();
                            ctor.setAccessible(true);
                            Object fakeAddr = ctor.newInstance();
                            Field addrField = ifAddrClass.getDeclaredField("address");
                            addrField.setAccessible(true);
                            addrField.set(fakeAddr, InetAddress.getByName(fakeIP));
                            List<Object> addrs = new ArrayList<>();
                            addrs.add(fakeAddr);
                            param.setResult(addrs);
                        } catch (Exception e) { }
                    }
                }
            });
        } catch (Throwable t) { }
    }

    // ====================================================================
    // 3. 网络层 - DhcpInfo / NetworkCapabilities / LinkProperties
    // ====================================================================
    private void hookNetworkLayer(ClassLoader cl) {
        hook("android.net.wifi.WifiManager", cl, "getDhcpInfo", p -> {
            try {
                android.net.DhcpInfo d = new android.net.DhcpInfo();
                d.ipAddress = ipToInt(fakeIP);
                d.gateway = ipToInt(fakeGateway);
                d.netmask = ipToInt(fakeNetmask);
                d.dns1 = ipToInt(fakeDNS1);
                d.dns2 = ipToInt(fakeDNS2);
                d.serverAddress = ipToInt(fakeGateway);
                d.leaseDuration = 86400;
                p.setResult(d);
            } catch (Throwable e) { }
        });

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            hook("android.net.NetworkCapabilities", cl, "getTransportInfo", p -> {
                if (p.getResult() instanceof WifiInfo) {
                    WifiInfo fake = buildFakeWifiInfo();
                    if (fake != null) p.setResult(fake);
                }
            });
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            hook("android.net.NetworkCapabilities", cl, "hasTransport", p -> {
                int type = (int) p.args[0];
                if (type == 0) p.setResult(true);
                if (type == 1) p.setResult(false);
                if (type == 3) p.setResult(false);
            });
        }

        try { hook("android.net.NetworkInfo", cl, "getExtraInfo", p -> p.setResult("\"" + fakeSSID + "\"")); }
        catch (Throwable t) { }

        try {
            findAndHookMethod("android.net.LinkAddress", cl, "getAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try { param.setResult(InetAddress.getByName(fakeIP)); } catch (Exception e) { }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod("android.net.LinkAddress", cl, "toString", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    param.setResult(fakeIP + "/24");
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod(InetAddress.class, "getHostAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String addr = (String) param.getResult();
                    if (addr != null && (addr.startsWith("192.168.") || addr.startsWith("10.") || addr.startsWith("172."))) {
                        if (!addr.equals(fakeIP)) param.setResult(fakeIP);
                    }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod(java.net.Inet4Address.class, "getHostAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String addr = (String) param.getResult();
                    if (addr != null && (addr.startsWith("192.168.") || addr.startsWith("10.") || addr.startsWith("172."))) {
                        param.setResult(fakeIP);
                    }
                }
            });
        } catch (Throwable t) { }

        // IPv6 EUI-64 过滤
        try {
            findAndHookMethod(java.net.Inet6Address.class, "getHostAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String addr = (String) param.getResult();
                    if (addr != null && (addr.startsWith("fe80:") || addr.startsWith("FE80:"))) {
                        param.setResult(generateFakeIPv6LinkLocal());
                    }
                }
            });
        } catch (Throwable t) { }

        // LinkProperties
        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getInterfaceName", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    param.setResult("wlan0");
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getLinkAddresses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Class<?> laClass = Class.forName("android.net.LinkAddress");
                        java.lang.reflect.Constructor<?> ctor = laClass.getConstructor(InetAddress.class, int.class);
                        Object la = ctor.newInstance(InetAddress.getByName(fakeIP), 24);
                        List<Object> list = new ArrayList<>();
                        list.add(la);
                        param.setResult(list);
                    } catch (Throwable e) { }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getDhcpServerAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try { param.setResult(InetAddress.getByName(fakeGateway)); } catch (Exception e) { }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getDnsServers", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        List<InetAddress> dns = new ArrayList<>();
                        dns.add(InetAddress.getByName(fakeDNS1));
                        dns.add(InetAddress.getByName(fakeDNS2));
                        param.setResult(dns);
                    } catch (Exception e) { }
                }
            });
        } catch (Throwable t) { }

        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getRoutes", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Class<?> riClass = Class.forName("android.net.RouteInfo");
                        java.lang.reflect.Constructor<?> ctor = riClass.getConstructor(InetAddress.class, InetAddress.class, String.class);
                        Object route = ctor.newInstance(InetAddress.getByName("0.0.0.0"), InetAddress.getByName(fakeGateway), "wlan0");
                        List<Object> list = new ArrayList<>();
                        list.add(route);
                        param.setResult(list);
                    } catch (Throwable e) { }
                }
            });
        } catch (Throwable t) { }
    }

    // ====================================================================
    // 4. WiFi扫描
    // ====================================================================
    private void hookScanResults(ClassLoader cl) {
        hook("android.net.wifi.WifiManager", cl, "getScanResults", p -> {
            @SuppressWarnings("unchecked")
            List<ScanResult> original = (List<ScanResult>) p.getResult();
            if (original == null) original = new ArrayList<>();

            boolean found = false;
            for (ScanResult sr : original) {
                if (fakeBSSID.equalsIgnoreCase(sr.BSSID)) {
                    sr.SSID = fakeSSID;
                    sr.frequency = fakeFrequency;
                    sr.level = fakeRSSI;
                    sr.capabilities = "[WPA2-PSK-CCMP][ESS]";
                    found = true;
                }
            }
            if (!found) {
                ScanResult fakeAP = createFakeScanResult();
                original.add(0, fakeAP);
            }
            p.setResult(original);
        });

        hook("android.net.wifi.WifiManager", cl, "startScan", p -> p.setResult(true));
    }

    // ====================================================================
    // 5. SystemProperties (统一)
    // ====================================================================
    private void hookSystemProperties(ClassLoader cl) {
        try {
            Class<?> spClass = Class.forName("android.os.SystemProperties");
            for (Method m : spClass.getDeclaredMethods()) {
                if ("get".equals(m.getName()) && m.getParameterCount() >= 1) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String key = (String) param.args[0];
                            if (key == null) return;
                            switch (key) {
                                case "wifi.interface": param.setResult("wlan0"); break;
                                case "wifi.direct.interface": param.setResult("p2p-dev-wlan0"); break;
                                case "ro.hardware.wifi": param.setResult("wlan"); break;
                                case "ro.build.tags": param.setResult("release-keys"); break;
                                case "ro.debuggable": param.setResult("0"); break;
                                case "ro.secure": param.setResult("1"); break;
                                case "ro.build.selinux": param.setResult("1"); break;
                                case "ro.build.type": param.setResult("user"); break;
                                case "init.svc.adbd": param.setResult("stopped"); break;
                                default:
                                    if (key.contains("magisk") || key.contains("supersu")) {
                                        param.setResult("");
                                    }
                                    break;
                            }
                        }
                    });
                }
            }
            writeLog("OK SystemProperties.get");
        } catch (Throwable t) { writeLog("FAIL SystemProperties: " + t.getMessage()); }
    }

    // ====================================================================
    // 6. 文件系统 (统一) - sysfs/proc/root路径全部在这里处理
    // ====================================================================
    private void hookFileSystem(ClassLoader cl) {
        // File.exists - 统一处理sysfs + root隐藏
        try {
            findAndHookMethod(java.io.File.class, "exists", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    File file = (File) param.thisObject;
                    String path = file.getAbsolutePath();

                    if (path.matches(".*/sys/class/net/.*/address")) {
                        param.setResult(true);
                        return;
                    }
                    if (isRootPath(path)) {
                        param.setResult(false);
                    }
                }
            });
        } catch (Throwable t) { writeLog("FAIL File.exists: " + t.getMessage()); }

        // File.canRead/canWrite/canExecute
        String[] accessMethods = {"canRead", "canWrite", "canExecute", "isFile", "isDirectory"};
        for (String methodName : accessMethods) {
            try {
                findAndHookMethod(java.io.File.class, methodName, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        File file = (File) param.thisObject;
                        if (isRootPath(file.getAbsolutePath())) {
                            param.setResult(false);
                        }
                    }
                });
            } catch (Throwable t) { }
        }

        // File.length - sysfs MAC
        try {
            findAndHookMethod(java.io.File.class, "length", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    File file = (File) param.thisObject;
                    if (file.getAbsolutePath().matches(".*/sys/class/net/.*/address")) {
                        param.setResult((long)(fakeMAC.toLowerCase() + "\n").getBytes().length);
                    }
                }
            });
        } catch (Throwable t) { }

        // File.listFiles - 过滤root相关文件
        try {
            findAndHookMethod(java.io.File.class, "listFiles", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    File[] files = (File[]) param.getResult();
                    if (files == null) return;
                    File dir = (File) param.thisObject;
                    String dirPath = dir.getAbsolutePath();
                    if (dirPath.startsWith("/system") || dirPath.startsWith("/sbin")
                        || dirPath.startsWith("/data/adb") || dirPath.startsWith("/su")) {
                        List<File> filtered = new ArrayList<>();
                        for (File f : files) {
                            if (!isRootPath(f.getAbsolutePath())) {
                                filtered.add(f);
                            }
                        }
                        param.setResult(filtered.toArray(new File[0]));
                    }
                }
            });
        } catch (Throwable t) { }

        // FileInputStream(String) - 统一重定向
        try {
            findAndHookMethod(java.io.FileInputStream.class, "<init>", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String path = (String) param.args[0];
                    if (path == null) return;

                    if (path.matches(".*/sys/class/net/.*/address")) {
                        try { param.args[0] = createFakeMacFile().getAbsolutePath(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/arp")) {
                        try { param.args[0] = createFakeArpFile().getAbsolutePath(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/if_inet6")) {
                        try { param.args[0] = createFakeInet6File().getAbsolutePath(); }
                        catch (Exception e) { }
                    }
                }
            });
        } catch (Throwable t) { writeLog("FAIL FileInputStream(String): " + t.getMessage()); }

        // FileInputStream(File) - 统一重定向
        try {
            findAndHookMethod(java.io.FileInputStream.class, "<init>", java.io.File.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    File file = (File) param.args[0];
                    if (file == null) return;
                    String path = file.getAbsolutePath();

                    if (path.matches(".*/sys/class/net/.*/address")) {
                        try { param.args[0] = createFakeMacFile(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/arp")) {
                        try { param.args[0] = createFakeArpFile(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/if_inet6")) {
                        try { param.args[0] = createFakeInet6File(); }
                        catch (Exception e) { }
                    }
                }
            });
        } catch (Throwable t) { writeLog("FAIL FileInputStream(File): " + t.getMessage()); }

        // FileReader(String)
        try {
            findAndHookMethod(java.io.FileReader.class, "<init>", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String path = (String) param.args[0];
                    if (path == null) return;

                    if (path.matches(".*/sys/class/net/.*/address")) {
                        try { param.args[0] = createFakeMacFile().getAbsolutePath(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/arp")) {
                        try { param.args[0] = createFakeArpFile().getAbsolutePath(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/if_inet6")) {
                        try { param.args[0] = createFakeInet6File().getAbsolutePath(); }
                        catch (Exception e) { }
                    }
                }
            });
        } catch (Throwable t) { }

        // FileReader(File)
        try {
            findAndHookMethod(java.io.FileReader.class, "<init>", java.io.File.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    File file = (File) param.args[0];
                    if (file == null) return;
                    String path = file.getAbsolutePath();

                    if (path.matches(".*/sys/class/net/.*/address")) {
                        try { param.args[0] = createFakeMacFile(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/arp")) {
                        try { param.args[0] = createFakeArpFile(); }
                        catch (Exception e) { }
                    } else if (path.equals("/proc/net/if_inet6")) {
                        try { param.args[0] = createFakeInet6File(); }
                        catch (Exception e) { }
                    }
                }
            });
        } catch (Throwable t) { }

        // BufferedReader.readLine - 统一处理MAC拦截 + proc过滤
        try {
            findAndHookMethod(BufferedReader.class, "readLine", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String line = (String) param.getResult();
                    if (line == null) return;

                    // MAC格式拦截
                    String trimmed = line.trim().toLowerCase();
                    if (trimmed.matches("[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}")) {
                        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                        for (StackTraceElement frame : stack) {
                            String cls = frame.getClassName();
                            if (cls.contains("NetworkInterface") || cls.contains("WifiInfo")
                                || cls.contains("LinkProperties") || cls.contains("InetAddress")) {
                                param.setResult(fakeMAC.toLowerCase());
                                return;
                            }
                        }
                    }

                    // /proc/self/maps 过滤Xposed/Magisk特征
                    if (containsRootSignature(line)) {
                        param.setResult(null);
                    }
                }
            });
        } catch (Throwable t) { writeLog("FAIL BufferedReader: " + t.getMessage()); }

        // NIO Files.readAllBytes
        try {
            Class<?> filesClass = Class.forName("java.nio.file.Files");
            findAndHookMethod(filesClass, "readAllBytes", java.nio.file.Path.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    java.nio.file.Path path = (java.nio.file.Path) param.args[0];
                    if (path != null && path.toString().matches(".*/sys/class/net/.*/address")) {
                        param.setResult((fakeMAC.toLowerCase() + "\n").getBytes());
                    }
                }
            });
        } catch (Throwable t) { }

        // NIO Files.readAllLines
        try {
            Class<?> filesClass = Class.forName("java.nio.file.Files");
            findAndHookMethod(filesClass, "readAllLines", java.nio.file.Path.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    java.nio.file.Path path = (java.nio.file.Path) param.args[0];
                    if (path != null && path.toString().matches(".*/sys/class/net/.*/address")) {
                        List<String> lines = new ArrayList<>();
                        lines.add(fakeMAC.toLowerCase());
                        param.setResult(lines);
                    }
                }
            });
        } catch (Throwable t) { }

        writeLog("OK FileSystem hooks (unified)");
    }

    // ====================================================================
    // 7. 命令执行 (统一) - Runtime.exec + ProcessBuilder
    // ====================================================================
    private void hookCommandExecution(ClassLoader cl) {
        // Runtime.exec(String)
        try {
            findAndHookMethod(Runtime.class, "exec", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String cmd = (String) param.args[0];
                    if (shouldBlockCommand(cmd)) {
                        param.setThrowable(new java.io.IOException("Permission denied"));
                    }
                }
            });
        } catch (Throwable t) { }

        // Runtime.exec(String[])
        try {
            findAndHookMethod(Runtime.class, "exec", String[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String[] cmds = (String[]) param.args[0];
                    if (cmds != null && cmds.length > 0 && shouldBlockCommand(joinArray(cmds))) {
                        param.setThrowable(new java.io.IOException("Permission denied"));
                    }
                }
            });
        } catch (Throwable t) { }

        // Runtime.exec(String, String[], File)
        try {
            findAndHookMethod(Runtime.class, "exec", String.class, String[].class, java.io.File.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String cmd = (String) param.args[0];
                    if (shouldBlockCommand(cmd)) {
                        param.setThrowable(new java.io.IOException("Permission denied"));
                    }
                }
            });
        } catch (Throwable t) { }

        // Runtime.exec(String[], String[], File)
        try {
            findAndHookMethod(Runtime.class, "exec", String[].class, String[].class, java.io.File.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String[] cmds = (String[]) param.args[0];
                    if (cmds != null && cmds.length > 0 && shouldBlockCommand(joinArray(cmds))) {
                        param.setThrowable(new java.io.IOException("Permission denied"));
                    }
                }
            });
        } catch (Throwable t) { }

        // ProcessBuilder.start
        try {
            findAndHookMethod(ProcessBuilder.class, "start", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    ProcessBuilder pb = (ProcessBuilder) param.thisObject;
                    List<String> cmds = pb.command();
                    if (cmds != null && !cmds.isEmpty() && shouldBlockCommand(joinList(cmds))) {
                        param.setThrowable(new java.io.IOException("Permission denied"));
                    }
                }
            });
        } catch (Throwable t) { }

        writeLog("OK Command execution hooks");
    }

    // ====================================================================
    // 8. Root隐藏 (PackageManager + Build字段)
    // ====================================================================
    private void hookRootHiding(ClassLoader cl) {
        // PackageManager.getPackageInfo
        try {
            findAndHookMethod("android.app.ApplicationPackageManager", cl, "getPackageInfo",
                String.class, int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String pkg = (String) param.args[0];
                        if (pkg != null && ROOT_PACKAGES.contains(pkg)) {
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException(pkg));
                        }
                    }
                });
        } catch (Throwable t) { writeLog("FAIL getPackageInfo: " + t.getMessage()); }

        // PackageManager.getInstalledPackages
        try {
            findAndHookMethod("android.app.ApplicationPackageManager", cl, "getInstalledPackages",
                int.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        @SuppressWarnings("unchecked")
                        List<Object> packages = (List<Object>) param.getResult();
                        if (packages == null) return;
                        List<Object> filtered = new ArrayList<>();
                        for (Object pkg : packages) {
                            try {
                                String name = (String) XposedHelpers.getObjectField(pkg, "packageName");
                                if (!ROOT_PACKAGES.contains(name)) filtered.add(pkg);
                            } catch (Throwable t2) { filtered.add(pkg); }
                        }
                        param.setResult(filtered);
                    }
                });
        } catch (Throwable t) { writeLog("FAIL getInstalledPackages: " + t.getMessage()); }

        // PackageManager.getInstalledApplications
        try {
            findAndHookMethod("android.app.ApplicationPackageManager", cl, "getInstalledApplications",
                int.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        @SuppressWarnings("unchecked")
                        List<Object> apps = (List<Object>) param.getResult();
                        if (apps == null) return;
                        List<Object> filtered = new ArrayList<>();
                        for (Object app : apps) {
                            try {
                                String name = (String) XposedHelpers.getObjectField(app, "packageName");
                                if (!ROOT_PACKAGES.contains(name)) filtered.add(app);
                            } catch (Throwable t2) { filtered.add(app); }
                        }
                        param.setResult(filtered);
                    }
                });
        } catch (Throwable t) { writeLog("FAIL getInstalledApplications: " + t.getMessage()); }

        // Build.TAGS 字段修改
        try {
            XposedHelpers.setStaticObjectField(Build.class, "TAGS", "release-keys");
            writeLog("OK Build.TAGS = release-keys");
        } catch (Throwable t) {
            try {
                Field tagsField = Build.class.getDeclaredField("TAGS");
                tagsField.setAccessible(true);
                tagsField.set(null, "release-keys");
            } catch (Throwable t2) { writeLog("FAIL Build.TAGS: " + t2.getMessage()); }
        }

        // Build.TYPE (有些检测器检查这个)
        try {
            XposedHelpers.setStaticObjectField(Build.class, "TYPE", "user");
        } catch (Throwable t) { }

        // Settings.Secure & Settings.Global
        try {
            findAndHookMethod("android.provider.Settings$Secure", cl, "getString",
                android.content.ContentResolver.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[1];
                        if (key == null) return;
                        switch (key) {
                            case "adb_enabled": param.setResult("0"); break;
                            case "development_settings_enabled": param.setResult("0"); break;
                            case "wifi_mac_address":
                            case "wifi_mac":
                                param.setResult(fakeMAC); break;
                            case "bluetooth_address":
                                param.setResult(generateFakeBluetoothMac()); break;
                        }
                    }
                });
        } catch (Throwable t) { writeLog("FAIL Settings.Secure: " + t.getMessage()); }

        try {
            findAndHookMethod("android.provider.Settings$Global", cl, "getString",
                android.content.ContentResolver.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[1];
                        if (key == null) return;
                        switch (key) {
                            case "adb_enabled": param.setResult("0"); break;
                            case "development_settings_enabled": param.setResult("0"); break;
                        }
                    }
                });
        } catch (Throwable t) { }

        writeLog("OK Root hiding hooks");
    }

    // ====================================================================
    // 9. MAC泄漏补全
    // ====================================================================
    private void hookMacLeaks(ClassLoader cl) {
        // WifiManager.getConfiguredNetworks
        try {
            hook("android.net.wifi.WifiManager", cl, "getConfiguredNetworks", p -> {
                try {
                    Class<?> wifiConfigClass = Class.forName("android.net.wifi.WifiConfiguration");
                    Object fakeConfig = wifiConfigClass.newInstance();
                    XposedHelpers.setObjectField(fakeConfig, "SSID", "\"" + fakeSSID + "\"");
                    XposedHelpers.setObjectField(fakeConfig, "BSSID", fakeBSSID);
                    XposedHelpers.setIntField(fakeConfig, "networkId", fakeNetworkId);
                    List<Object> list = new ArrayList<>();
                    list.add(fakeConfig);
                    p.setResult(list);
                } catch (Throwable t2) { }
            });
        } catch (Throwable t) { }

        // WifiInfo.getInformationElements (Android 12+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                hook("android.net.wifi.WifiInfo", cl, "getInformationElements", p -> p.setResult(null));
            } catch (Throwable t) { }
        }

        // WifiInfo的其他可能泄漏方法
        try { hook("android.net.wifi.WifiInfo", cl, "getPasspointFqdn", p -> p.setResult(null)); }
        catch (Throwable t) { }
        try { hook("android.net.wifi.WifiInfo", cl, "getPasspointProviderFriendlyName", p -> p.setResult(null)); }
        catch (Throwable t) { }

        writeLog("OK MAC leak patches");
    }

    // ====================================================================
    // 判断方法
    // ====================================================================
    private boolean shouldBlockCommand(String cmd) {
        if (cmd == null) return false;
        String lower = cmd.toLowerCase().trim();

        // Root检测命令
        if (lower.equals("su") || lower.startsWith("su ") || lower.endsWith("/su")) return true;
        if (lower.contains("which su") || lower.contains("type su")) return true;
        if (lower.equals("id") || lower.equals("whoami")) return true;
        if (lower.contains("magisk") || lower.contains("busybox")) return true;
        if (lower.contains("getprop") && (lower.contains("ro.build.tags")
            || lower.contains("ro.debuggable") || lower.contains("ro.secure"))) return true;

        // MAC泄漏命令
        if (lower.startsWith("ip link") || lower.startsWith("ip addr")
            || lower.startsWith("ip -d link") || lower.startsWith("ip a")) return true;
        if (lower.startsWith("ifconfig") || lower.contains("/ifconfig")) return true;
        if (lower.contains("cat") && lower.contains("/sys/class/net") && lower.contains("address")) return true;
        if (lower.contains("cat") && (lower.contains("/proc/net/arp") || lower.contains("/proc/net/if_inet6"))) return true;
        if (lower.startsWith("netcfg") || lower.contains("/netcfg")) return true;
        if (lower.contains("getprop") && lower.contains("wifi")) return true;

        // 路径检测
        for (String path : ROOT_PATHS) {
            if (lower.contains(path)) return true;
        }

        return false;
    }

    private boolean isRootPath(String path) {
        if (path == null) return false;
        if (ROOT_PATHS.contains(path)) return true;
        String lower = path.toLowerCase();
        if ((lower.contains("/su") || lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("busybox") || lower.contains("xposed")
            || lower.contains("lsposed") || lower.contains("edxposed")
            || lower.contains("riru") || lower.contains("zygisk"))
            && (path.startsWith("/system") || path.startsWith("/sbin")
                || path.startsWith("/data/adb") || path.startsWith("/data/local")
                || path.startsWith("/su") || path.startsWith("/cache"))) {
            return true;
        }
        return false;
    }

    private boolean containsRootSignature(String line) {
        if (line == null) return false;
        String lower = line.toLowerCase();
        return lower.contains("xposed") || lower.contains("magisk")
            || lower.contains("supersu") || lower.contains("substrate")
            || lower.contains("lsposed") || lower.contains("edxposed")
            || lower.contains("riru") || lower.contains("zygisk")
            || lower.contains("libxposed") || lower.contains("liblspd");
    }

    // ====================================================================
    // 辅助方法
    // ====================================================================
    private WifiInfo buildFakeWifiInfo() {
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            Method allocate = unsafeClass.getMethod("allocateInstance", Class.class);
            WifiInfo info = (WifiInfo) allocate.invoke(unsafe, WifiInfo.class);

            setField(info, "mBssid", fakeBSSID);
            setField(info, "mBSSID", fakeBSSID);
            setField(info, "mMacAddress", fakeMAC);
            setField(info, "mSSID", "\"" + fakeSSID + "\"");
            setIntFieldSafe(info, "mNetworkId", fakeNetworkId);
            setIntFieldSafe(info, "mRssi", fakeRSSI);
            setIntFieldSafe(info, "mLinkSpeed", fakeLinkSpeed);
            setIntFieldSafe(info, "mFrequency", fakeFrequency);
            setIntFieldSafe(info, "mIpAddress", ipToInt(fakeIP));
            return info;
        } catch (Throwable t) {
            return null;
        }
    }

    private ScanResult createFakeScanResult() {
        ScanResult sr = new ScanResult();
        sr.BSSID = fakeBSSID;
        sr.SSID = fakeSSID;
        sr.frequency = fakeFrequency;
        sr.level = fakeRSSI;
        sr.capabilities = "[WPA2-PSK-CCMP][ESS]";
        return sr;
    }

    private String generateFakeIPv6LinkLocal() {
        try {
            String[] p = fakeMAC.split(":");
            int first = Integer.parseInt(p[0], 16) ^ 0x02;
            return String.format("fe80::%02x%s:%sff:fe%s:%s%s", first, p[1], p[2], p[3], p[4], p[5]);
        } catch (Exception e) { return "fe80::1"; }
    }

    private String generateFakeBluetoothMac() {
        try {
            String[] p = fakeMAC.split(":");
            int last = (Integer.parseInt(p[5], 16) + 1) & 0xFF;
            return String.format("%s:%s:%s:%s:%s:%02X", p[0], p[1], p[2], p[3], p[4], last);
        } catch (Exception e) { return fakeMAC; }
    }

    private File createFakeMacFile() throws Exception {
        File tmp = File.createTempFile("net_", ".dat");
        tmp.deleteOnExit();
        FileWriter fw = new FileWriter(tmp);
        fw.write(fakeMAC.toLowerCase() + "\n");
        fw.close();
        return tmp;
    }

    private File createFakeArpFile() throws Exception {
        File tmp = File.createTempFile("net_arp_", ".dat");
        tmp.deleteOnExit();
        FileWriter fw = new FileWriter(tmp);
        fw.write("IP address       HW type     Flags       HW address            Mask     Device\n");
        fw.write(fakeGateway + "     0x1         0x2         " + fakeBSSID.toLowerCase() + "     *        wlan0\n");
        fw.close();
        return tmp;
    }

    private File createFakeInet6File() throws Exception {
        File tmp = File.createTempFile("net_v6_", ".dat");
        tmp.deleteOnExit();
        FileWriter fw = new FileWriter(tmp);
        String eui64 = macToEui64(fakeMAC);
        fw.write("fe80" + "00000000" + "00000000" + eui64 + " 03 40 20 80 wlan0\n");
        fw.write("00000000000000000000000000000001 01 80 10 80       lo\n");
        fw.close();
        return tmp;
    }

    private String macToEui64(String mac) {
        try {
            String[] p = mac.split(":");
            int first = Integer.parseInt(p[0], 16) ^ 0x02;
            return String.format("%02x%s%sff" + "fe%s%s%s", first, p[1], p[2], p[3], p[4], p[5]);
        } catch (Exception e) { return "0000000000000000"; }
    }

    private void hook(String className, ClassLoader cl, String method, final HookCallback cb) {
        try {
            findAndHookMethod(className, cl, method, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try { cb.onHook(param); } catch (Throwable t) { }
                }
            });
        } catch (Throwable t) { writeLog("FAIL " + className + "." + method + ": " + t.getMessage()); }
    }

    private interface HookCallback { void onHook(XC_MethodHook.MethodHookParam param) throws Throwable; }

    private void setField(Object obj, String name, Object value) {
        try {
            Class<?> clazz = obj.getClass();
            while (clazz != null) {
                try {
                    Field f = clazz.getDeclaredField(name);
                    f.setAccessible(true);
                    f.set(obj, value);
                    return;
                } catch (NoSuchFieldException e) { clazz = clazz.getSuperclass(); }
            }
        } catch (Throwable t) { }
    }

    private void setIntFieldSafe(Object obj, String name, int value) {
        try {
            Class<?> clazz = obj.getClass();
            while (clazz != null) {
                try {
                    Field f = clazz.getDeclaredField(name);
                    f.setAccessible(true);
                    f.setInt(obj, value);
                    return;
                } catch (NoSuchFieldException e) { clazz = clazz.getSuperclass(); }
            }
        } catch (Throwable t) { }
    }

    private int ipToInt(String ip) {
        try {
            String[] p = ip.split("\\.");
            return (Integer.parseInt(p[0]) & 0xFF)
                | ((Integer.parseInt(p[1]) & 0xFF) << 8)
                | ((Integer.parseInt(p[2]) & 0xFF) << 16)
                | ((Integer.parseInt(p[3]) & 0xFF) << 24);
        } catch (Exception e) { return 0; }
    }

    private byte[] parseMac(String mac) {
        if (mac == null) return null;
        String[] parts = mac.split(":");
        if (parts.length != 6) return null;
        byte[] r = new byte[6];
        for (int i = 0; i < 6; i++) r[i] = (byte) Integer.parseInt(parts[i], 16);
        return r;
    }

    private String joinArray(String[] arr) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < arr.length; i++) { if (i > 0) sb.append(" "); sb.append(arr[i]); }
        return sb.toString();
    }

    private String joinList(List<String> list) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) { if (i > 0) sb.append(" "); sb.append(list.get(i)); }
        return sb.toString();
    }

    // ====================================================================
    // 配置读取
    // ====================================================================
    private void loadConfig(ClassLoader cl, String packageName) {
        try {
            XSharedPreferences xPrefs = new XSharedPreferences(PKG_SELF, PREF_NAME);
            xPrefs.makeWorldReadable();
            xPrefs.reload();
            if (xPrefs.getFile().exists() && xPrefs.getFile().canRead()) {
                readPrefs(xPrefs);
                writeLog("Config: XSharedPreferences OK");
                return;
            }
        } catch (Throwable t) { }

        try { loadConfigFromExternalFile(); return; }
        catch (Throwable t) { }

        try { loadConfigFromFile(); return; }
        catch (Throwable t) { }

        try {
            Object at = XposedHelpers.callStaticMethod(
                Class.forName("android.app.ActivityThread"), "currentActivityThread");
            Object sysCtx = XposedHelpers.callMethod(at, "getSystemContext");
            Object spoofCtx = XposedHelpers.callMethod(sysCtx, "createPackageContext", PKG_SELF, 2);
            Object prefs = XposedHelpers.callMethod(spoofCtx, "getSharedPreferences", PREF_NAME, 0);
            enabled = (Boolean) XposedHelpers.callMethod(prefs, "getBoolean", "spoof_enabled", true);
            fakeBSSID = (String) XposedHelpers.callMethod(prefs, "getString", "fake_bssid", "AA:BB:CC:DD:EE:FF");
            fakeMAC = (String) XposedHelpers.callMethod(prefs, "getString", "fake_mac", "AA:BB:CC:DD:EE:FF");
            String rawSSID = (String) XposedHelpers.callMethod(prefs, "getString", "fake_ssid", "\"MyHomeWiFi\"");
            fakeSSID = rawSSID.replace("\"", "");
            fakeIP = (String) XposedHelpers.callMethod(prefs, "getString", "fake_ip", "192.168.1.100");
            fakeGateway = (String) XposedHelpers.callMethod(prefs, "getString", "fake_gateway", "192.168.1.1");
            fakeNetmask = (String) XposedHelpers.callMethod(prefs, "getString", "fake_netmask", "255.255.255.0");
            fakeDNS1 = (String) XposedHelpers.callMethod(prefs, "getString", "fake_dns1", "8.8.8.8");
            fakeDNS2 = (String) XposedHelpers.callMethod(prefs, "getString", "fake_dns2", "8.8.4.4");
            fakeFrequency = (int)(Integer) XposedHelpers.callMethod(prefs, "getInt", "fake_frequency", 5180);
            fakeLinkSpeed = (int)(Integer) XposedHelpers.callMethod(prefs, "getInt", "fake_link_speed", 72);
            fakeRSSI = (int)(Integer) XposedHelpers.callMethod(prefs, "getInt", "fake_rssi", -45);
        } catch (Throwable t) {
            writeLog("ALL CONFIG METHODS FAILED - defaults used");
        }
    }

    private void readPrefs(XSharedPreferences prefs) {
        enabled = prefs.getBoolean("spoof_enabled", true);
        fakeBSSID = prefs.getString("fake_bssid", "AA:BB:CC:DD:EE:FF");
        fakeMAC = prefs.getString("fake_mac", "AA:BB:CC:DD:EE:FF");
        String rawSSID = prefs.getString("fake_ssid", "\"MyHomeWiFi\"");
        fakeSSID = rawSSID.replace("\"", "");
        fakeIP = prefs.getString("fake_ip", "192.168.1.100");
        fakeGateway = prefs.getString("fake_gateway", "192.168.1.1");
        fakeNetmask = prefs.getString("fake_netmask", "255.255.255.0");
        fakeDNS1 = prefs.getString("fake_dns1", "8.8.8.8");
        fakeDNS2 = prefs.getString("fake_dns2", "8.8.4.4");
        fakeFrequency = prefs.getInt("fake_frequency", 5180);
        fakeLinkSpeed = prefs.getInt("fake_link_speed", 72);
        fakeRSSI = prefs.getInt("fake_rssi", -45);
    }

    private void loadConfigFromExternalFile() throws Throwable {
        String[] paths = {
            "/sdcard/wifi_spoof_config.txt",
            "/sdcard/Android/data/com.fakespoof.wifispoof/wifi_spoof_config.txt",
            "/storage/emulated/0/wifi_spoof_config.txt",
            "/data/local/tmp/wifi_spoof_config.txt",
            "/sdcard/Android/data/com.fakespoof.wifispoof/files/wifi_spoof_config.txt"
        };
        File configFile = null;
        for (String path : paths) {
            File f = new File(path);
            if (f.exists() && f.length() > 0) { configFile = f; break; }
        }
        if (configFile == null) throw new Exception("Not found");

        BufferedReader reader = new BufferedReader(new java.io.FileReader(configFile));
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.startsWith("enabled=")) enabled = "true".equals(line.substring(8));
            else if (line.startsWith("bssid=")) fakeBSSID = line.substring(6);
            else if (line.startsWith("mac=")) fakeMAC = line.substring(4);
            else if (line.startsWith("ssid=")) fakeSSID = line.substring(5).replace("\"", "");
            else if (line.startsWith("ip=")) fakeIP = line.substring(3);
            else if (line.startsWith("gateway=")) fakeGateway = line.substring(8);
            else if (line.startsWith("netmask=")) fakeNetmask = line.substring(8);
            else if (line.startsWith("dns1=")) fakeDNS1 = line.substring(5);
            else if (line.startsWith("dns2=")) fakeDNS2 = line.substring(5);
        }
        reader.close();
    }

    private void loadConfigFromFile() throws Throwable {
        String[] paths = {
            "/data/data/" + PKG_SELF + "/shared_prefs/" + PREF_NAME + ".xml",
            "/data/user/0/" + PKG_SELF + "/shared_prefs/" + PREF_NAME + ".xml",
            "/data/user_de/0/" + PKG_SELF + "/shared_prefs/" + PREF_NAME + ".xml"
        };
        File prefsFile = null;
        for (String path : paths) {
            File f = new File(path);
            if (f.exists()) { prefsFile = f; break; }
        }
        if (prefsFile == null) throw new Exception("Not found");

        BufferedReader reader = new BufferedReader(new java.io.FileReader(prefsFile));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        reader.close();

        String xml = sb.toString();
        enabled = parseXmlBool(xml, "spoof_enabled", true);
        fakeBSSID = parseXmlString(xml, "fake_bssid", "AA:BB:CC:DD:EE:FF");
        fakeMAC = parseXmlString(xml, "fake_mac", "AA:BB:CC:DD:EE:FF");
        fakeSSID = parseXmlString(xml, "fake_ssid", "\"MyHomeWiFi\"").replace("\"", "");
        fakeIP = parseXmlString(xml, "fake_ip", "192.168.1.100");
        fakeGateway = parseXmlString(xml, "fake_gateway", "192.168.1.1");
        fakeNetmask = parseXmlString(xml, "fake_netmask", "255.255.255.0");
        fakeDNS1 = parseXmlString(xml, "fake_dns1", "8.8.8.8");
        fakeDNS2 = parseXmlString(xml, "fake_dns2", "8.8.4.4");
        fakeFrequency = parseXmlInt(xml, "fake_frequency", 5180);
        fakeLinkSpeed = parseXmlInt(xml, "fake_link_speed", 72);
        fakeRSSI = parseXmlInt(xml, "fake_rssi", -45);
    }

    private String parseXmlString(String xml, String key, String def) {
        try {
            String s = "name=\"" + key + "\">";
            int start = xml.indexOf(s);
            if (start < 0) return def;
            start += s.length();
            int end = xml.indexOf("<", start);
            if (end < 0) return def;
            return xml.substring(start, end).replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&quot;", "\"");
        } catch (Exception e) { return def; }
    }

    private boolean parseXmlBool(String xml, String key, boolean def) {
        return "true".equals(parseXmlString(xml, key, String.valueOf(def)));
    }

    private int parseXmlInt(String xml, String key, int def) {
        try { return Integer.parseInt(parseXmlString(xml, key, String.valueOf(def))); }
        catch (Exception e) { return def; }
    }

    private void writeLog(String msg) {
        try {
            PrintWriter pw = new PrintWriter(new FileWriter(new File(LOG_FILE), true));
            pw.println(System.currentTimeMillis() + " " + msg);
            pw.flush();
            pw.close();
        } catch (Exception e) { }
    }
}
