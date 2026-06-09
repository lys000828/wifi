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
import java.util.Enumeration;
import java.util.List;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.setObjectField;
import static de.robv.android.xposed.XposedHelpers.setIntField;
import static de.robv.android.xposed.XposedHelpers.getIntField;

public class HookModule implements IXposedHookLoadPackage {
    private static final String TAG = "WifiSpoof";
    private static final String PREF_NAME = "wifi_spoof_config";
    private static final String PKG_SELF = "com.fakespoof.wifispoof";

    // 伪造值
    private String fakeBSSID = "AA:BB:CC:DD:EE:FF";
    private String fakeMAC = "AA:BB:CC:DD:EE:FF";
    private String fakeSSID = "MyHomeWiFi";  // 不带引号
    private boolean enabled = true;

    // 伪造网络参数
    private final String fakeIP = "192.168.1.100";
    private final String fakeGateway = "192.168.1.1";
    private final String fakeDNS1 = "8.8.8.8";
    private final String fakeDNS2 = "8.8.4.4";
    private final int fakeFrequency = 5180;
    private final int fakeLinkSpeed = 72;
    private final int fakeRSSI = -45;
    private final int fakeNetworkId = 1;

    // 日志文件路径
    private static final String LOG_FILE = "/sdcard/wifispoof_hook.log";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName.equals(PKG_SELF)) return;

        // 清空旧日志
        writeLog("=== WifiSpoof Hook Log ===");
        writeLog("Package: " + lpparam.packageName);
        writeLog("Time: " + System.currentTimeMillis());

        loadConfig(lpparam.classLoader);
        if (!enabled) {
            writeLog("STATUS: DISABLED, skip " + lpparam.packageName);
            XposedBridge.log(TAG + ": disabled, skip " + lpparam.packageName);
            return;
        }

        writeLog("Config: BSSID=" + fakeBSSID + " MAC=" + fakeMAC + " SSID=" + fakeSSID);
        XposedBridge.log(TAG + ": hooks → " + lpparam.packageName
            + " [" + fakeBSSID + " | " + fakeMAC + " | " + fakeSSID + "]");

        // 5个层面全部hook
        writeLog("--- Starting hooks ---");
        hookAppLayer(lpparam.classLoader);       // 1. App层API
        hookJavaLayer(lpparam.classLoader);      // 2. Java层
        hookSystemProperties(lpparam.classLoader); // 3. 系统属性
        hookNetworkLayer(lpparam.classLoader);   // 4. 底层网络
        hookScanResults(lpparam.classLoader);    // 5. WiFi扫描

        writeLog("--- All hooks installed ---");
        XposedBridge.log(TAG + ": all 5 layers hooked for " + lpparam.packageName);
    }

    // ====================================================================
    // 1. App层API - WifiManager / WifiInfo
    // ====================================================================
    private void hookAppLayer(ClassLoader cl) {
        // getConnectionInfo → 返回伪造WifiInfo
        hook("android.net.wifi.WifiManager", cl, "getConnectionInfo", p -> {
            p.setResult(buildFakeWifiInfo());
        });

        // getBSSID
        hook("android.net.wifi.WifiInfo", cl, "getBSSID", p -> p.setResult(fakeBSSID));

        // getSSID
        hook("android.net.wifi.WifiInfo", cl, "getSSID", p -> p.setResult("\"" + fakeSSID + "\""));

        // getMacAddress
        hook("android.net.wifi.WifiInfo", cl, "getMacAddress", p -> p.setResult(fakeMAC));

        // getNetworkId
        hook("android.net.wifi.WifiInfo", cl, "getNetworkId", p -> p.setResult(fakeNetworkId));

        // getRssi
        hook("android.net.wifi.WifiInfo", cl, "getRssi", p -> p.setResult(fakeRSSI));

        // getLinkSpeed
        hook("android.net.wifi.WifiInfo", cl, "getLinkSpeed", p -> p.setResult(fakeLinkSpeed));

        // getFrequency
        hook("android.net.wifi.WifiInfo", cl, "getFrequency", p -> p.setResult(fakeFrequency));

        // getIpAddress → 伪造IP
        hook("android.net.wifi.WifiInfo", cl, "getIpAddress", p -> {
            p.setResult(ipToInt(fakeIP));
        });

        // getServerAddress
        hook("android.net.wifi.WifiInfo", cl, "getServerAddress", p -> {
            p.setResult(ipToInt(fakeGateway));
        });

        // isWifiEnabled
        hook("android.net.wifi.WifiManager", cl, "isWifiEnabled", p -> p.setResult(true));

        // getWifiState
        hook("android.net.wifi.WifiManager", cl, "getWifiState", p -> p.setResult(3));
    }

    // ====================================================================
    // 2. Java层 - NetworkInterface
    // ====================================================================
    private void hookJavaLayer(ClassLoader cl) {
        // getHardwareAddress → 伪造wlan0的MAC
        try {
            findAndHookMethod(NetworkInterface.class, "getHardwareAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NetworkInterface ni = (NetworkInterface) param.thisObject;
                    if ("wlan0".equals(ni.getName())) {
                        param.setResult(parseMac(fakeMAC));
                    }
                }
            });
            writeLog("✓ NetworkInterface.getHardwareAddress");
        } catch (Throwable t) {
            writeLog("✗ NetworkInterface.getHardwareAddress: " + t.getMessage());
        }

        // getByName("wlan0") → 确保返回wlan0
        try {
            findAndHookMethod(NetworkInterface.class, "getByName", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String name = (String) param.args[0];
                    if (name != null && (name.equals("eth0") || name.contains("veth"))) {
                        try {
                            param.setResult(NetworkInterface.getByName("wlan0"));
                        } catch (Exception e) {
                            // 忽略
                        }
                    }
                }
            });
            writeLog("✓ NetworkInterface.getByName");
        } catch (Throwable t) {
            writeLog("✗ NetworkInterface.getByName: " + t.getMessage());
        }

        // getNetworkInterfaces → 确保wlan0在列表中
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
                        } catch (Exception e) {
                            // 忽略
                        }
                    }

                    param.setResult(java.util.Collections.enumeration(list));
                }
            });
            writeLog("✓ NetworkInterface.getNetworkInterfaces");
        } catch (Throwable t) {
            writeLog("✗ NetworkInterface.getNetworkInterfaces: " + t.getMessage());
        }

        // getName / getDisplayName → eth0/veth → wlan0
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
            writeLog("✓ NetworkInterface.getName");
        } catch (Throwable t) {
            writeLog("✗ NetworkInterface.getName: " + t.getMessage());
        }

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
            writeLog("✓ NetworkInterface.getDisplayName");
        } catch (Throwable t) {
            writeLog("✗ NetworkInterface.getDisplayName: " + t.getMessage());
        }

        // getInetAddresses → 伪造IP
        try {
            findAndHookMethod(NetworkInterface.class, "getInetAddresses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NetworkInterface ni = (NetworkInterface) param.thisObject;
                    if ("wlan0".equals(ni.getName())) {
                        try {
                            InetAddress fakeAddr = InetAddress.getByName(fakeIP);
                            List<InetAddress> addrs = new ArrayList<>();
                            addrs.add(fakeAddr);
                            param.setResult(java.util.Collections.enumeration(addrs));
                        } catch (Exception e) {
                            // 忽略
                        }
                    }
                }
            });
            writeLog("✓ NetworkInterface.getInetAddresses");
        } catch (Throwable t) {
            writeLog("✗ NetworkInterface.getInetAddresses: " + t.getMessage());
        }
    }

    // ====================================================================
    // 3. 系统属性 - SystemProperties / sysfs
    // ====================================================================
    private void hookSystemProperties(ClassLoader cl) {
        // android.os.SystemProperties.get
        try {
            Class<?> spClass = Class.forName("android.os.SystemProperties");
            for (Method m : spClass.getDeclaredMethods()) {
                if ("get".equals(m.getName()) && m.getParameterCount() >= 1) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String key = (String) param.args[0];
                            if (key == null) return;

                            if (key.equals("wifi.interface")) {
                                param.setResult("wlan0");
                            } else if (key.equals("wifi.direct.interface")) {
                                param.setResult("p2p-dev-wlan0");
                            } else if (key.equals("ro.hardware.wifi")) {
                                param.setResult("wlan");
                            }
                        }
                    });
                }
            }
            writeLog("✓ SystemProperties.get (all overloads)");
        } catch (Throwable t) {
            writeLog("✗ SystemProperties.get: " + t.getMessage());
        }

        // BufferedReader.readLine → 伪造sysfs MAC
        try {
            findAndHookMethod(BufferedReader.class, "readLine", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                    for (StackTraceElement frame : stack) {
                        String cls = frame.getClassName();
                        if (cls.contains("NetworkInterface") || cls.contains("LinuxNet")) {
                            String original = (String) param.getResult();
                            if (original != null && original.trim().toLowerCase().matches("[0-9a-f:]{17}")) {
                                param.setResult(fakeMAC.toLowerCase());
                            }
                            break;
                        }
                    }
                }
            });
            writeLog("✓ BufferedReader.readLine (sysfs MAC)");
        } catch (Throwable t) {
            writeLog("✗ BufferedReader.readLine: " + t.getMessage());
        }

        // File构造 → 替换sysfs路径
        try {
            findAndHookMethod(java.io.File.class, "<init>", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String path = (String) param.args[0];
                    if (path != null && path.contains("/sys/class/net/") && path.contains("/address")) {
                        try {
                            java.io.File tmp = java.io.File.createTempFile("fake_mac", ".tmp");
                            tmp.deleteOnExit();
                            java.io.FileWriter fw = new java.io.FileWriter(tmp);
                            fw.write(fakeMAC.toLowerCase());
                            fw.close();
                            param.args[0] = tmp.getAbsolutePath();
                        } catch (Exception e) {
                            // 忽略
                        }
                    }
                }
            });
            writeLog("✓ File.<init> (sysfs path)");
        } catch (Throwable t) {
            writeLog("✗ File.<init>: " + t.getMessage());
        }
    }

    // ====================================================================
    // 4. 底层网络 - DhcpInfo / NetworkCapabilities
    // ====================================================================
    private void hookNetworkLayer(ClassLoader cl) {
        // getDhcpInfo → 返回伪造DhcpInfo
        hook("android.net.wifi.WifiManager", cl, "getDhcpInfo", p -> {
            try {
                android.net.DhcpInfo fakeDhcp = new android.net.DhcpInfo();
                fakeDhcp.ipAddress = ipToInt(fakeIP);
                fakeDhcp.gateway = ipToInt(fakeGateway);
                fakeDhcp.netmask = ipToInt("255.255.255.0");
                fakeDhcp.dns1 = ipToInt(fakeDNS1);
                fakeDhcp.dns2 = ipToInt(fakeDNS2);
                fakeDhcp.serverAddress = ipToInt(fakeGateway);
                fakeDhcp.leaseDuration = 86400;
                p.setResult(fakeDhcp);
            } catch (Exception e) {
                XposedBridge.log(TAG + ": build fake DhcpInfo failed: " + e.getMessage());
            }
        });

        // NetworkCapabilities.getTransportInfo → 返回伪造WifiInfo (Android 11+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            hook("android.net.NetworkCapabilities", cl, "getTransportInfo", p -> {
                Object result = p.getResult();
                if (result instanceof WifiInfo) {
                    p.setResult(buildFakeWifiInfo());
                }
            });

            // hasTransport → WiFi=true
            hook("android.net.NetworkCapabilities", cl, "hasTransport", p -> {
                int type = (int) p.args[0];
                if (type == 0) p.setResult(true);  // TRANSPORT_WIFI
                if (type == 1) p.setResult(false); // TRANSPORT_CELLULAR
                if (type == 3) p.setResult(false); // TRANSPORT_ETHERNET
            });
        }
    }

    // ====================================================================
    // 5. WiFi扫描 - getScanResults / ScanResult
    // ====================================================================
    private void hookScanResults(ClassLoader cl) {
        // getScanResults → 注入伪造AP
        hook("android.net.wifi.WifiManager", cl, "getScanResults", p -> {
            @SuppressWarnings("unchecked")
            List<ScanResult> original = (List<ScanResult>) p.getResult();
            if (original == null) original = new ArrayList<>();

            // 检查是否已有匹配的BSSID
            boolean found = false;
            for (ScanResult sr : original) {
                if (fakeBSSID.equalsIgnoreCase(sr.BSSID)) {
                    sr.SSID = fakeSSID;
                    sr.frequency = fakeFrequency;
                    sr.level = fakeRSSI;
                    sr.capabilities = "[WPA2-PSK-CCMP][ESS]";
                    found = true;
                    break;
                }
            }

            // 没有就插入伪造AP
            if (!found) {
                ScanResult fakeAP = createFakeScanResult();
                original.add(0, fakeAP);
            }

            p.setResult(original);
        });

        // startScan → 返回true
        hook("android.net.wifi.WifiManager", cl, "startScan", p -> p.setResult(true));
    }

    // ====================================================================
    // 辅助方法
    // ====================================================================

    // 构建伪造的WifiInfo对象
    private WifiInfo buildFakeWifiInfo() {
        try {
            // 通过Unsafe创建WifiInfo实例（绕过构造函数）
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            java.lang.reflect.Method allocate = unsafeClass.getMethod("allocateInstance", Class.class);
            WifiInfo info = (WifiInfo) allocate.invoke(unsafe, WifiInfo.class);

            // 通过反射设置字段
            setField(info, "mBssid", fakeBSSID);
            setField(info, "mMacAddress", fakeMAC);
            setField(info, "mSSID", "\"" + fakeSSID + "\"");
            setIntField(info, "mNetworkId", fakeNetworkId);
            setIntField(info, "mRssi", fakeRSSI);
            setIntField(info, "mLinkSpeed", fakeLinkSpeed);
            setIntField(info, "mFrequency", fakeFrequency);
            setIntField(info, "mIpAddress", ipToInt(fakeIP));

            return info;
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": buildFakeWifiInfo failed: " + t.getMessage());
            return null;
        }
    }

    // 创建伪造的ScanResult
    private ScanResult createFakeScanResult() {
        ScanResult sr = new ScanResult();
        sr.BSSID = fakeBSSID;
        sr.SSID = fakeSSID;
        sr.frequency = fakeFrequency;
        sr.level = fakeRSSI;
        sr.capabilities = "[WPA2-PSK-CCMP][ESS]";
        // SSIDLength在新版Android已移除，用反射设置
        try {
            java.lang.reflect.Field f = ScanResult.class.getField("SSIDLength");
            f.setInt(sr, fakeSSID.length());
        } catch (Exception e) {
            // 忽略，旧版本才有这个字段
        }
        return sr;
    }

    // 通用hook封装 - 用匿名内部类，兼容所有Xposed版本
    private void hook(String className, ClassLoader cl, String method,
                      final HookCallback callback) {
        try {
            findAndHookMethod(className, cl, method, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        callback.onHook(param);
                    } catch (Throwable t) {
                        String msg = "✗ " + method + " callback ERROR: " + t.getMessage();
                        writeLog(msg);
                        XposedBridge.log(TAG + ": " + msg);
                    }
                }
            });
            writeLog("✓ " + className + "." + method);
            XposedBridge.log(TAG + ": ✓ hook " + className + "." + method);
        } catch (Throwable t) {
            String msg = "✗ " + className + "." + method + " FAILED: " + t.getMessage();
            writeLog(msg);
            XposedBridge.log(TAG + ": " + msg);
        }
    }

    // 简单回调接口
    private interface HookCallback {
        void onHook(XC_MethodHook.MethodHookParam param) throws Throwable;
    }

    // 设置对象字段（含父类）
    private void setField(Object obj, String name, Object value) {
        try {
            Class<?> clazz = obj.getClass();
            while (clazz != null) {
                try {
                    Field f = clazz.getDeclaredField(name);
                    f.setAccessible(true);
                    f.set(obj, value);
                    return;
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
        } catch (Throwable t) {
            // 忽略
        }
    }

    // IP字符串转int
    private int ipToInt(String ip) {
        try {
            String[] parts = ip.split("\\.");
            return (Integer.parseInt(parts[0]) & 0xFF)
                 | ((Integer.parseInt(parts[1]) & 0xFF) << 8)
                 | ((Integer.parseInt(parts[2]) & 0xFF) << 16)
                 | ((Integer.parseInt(parts[3]) & 0xFF) << 24);
        } catch (Exception e) {
            return 0;
        }
    }

    // MAC字符串转字节数组
    private byte[] parseMac(String mac) {
        if (mac == null) return null;
        String[] parts = mac.split(":");
        if (parts.length != 6) return null;
        byte[] result = new byte[6];
        for (int i = 0; i < 6; i++) {
            result[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return result;
    }

    // 从SharedPreferences读取配置
    private void loadConfig(ClassLoader cl) {
        try {
            Object at = XposedHelpers.callStaticMethod(
                Class.forName("android.app.ActivityThread"), "currentActivityThread");
            Object ctx = XposedHelpers.callMethod(at, "getSystemContext");
            Object prefs = XposedHelpers.callMethod(ctx, "getSharedPreferences", PREF_NAME, 0);

            enabled = (Boolean) XposedHelpers.callMethod(prefs, "getBoolean", "spoof_enabled", true);
            fakeBSSID = (String) XposedHelpers.callMethod(prefs, "getString", "fake_bssid", "AA:BB:CC:DD:EE:FF");
            fakeMAC = (String) XposedHelpers.callMethod(prefs, "getString", "fake_mac", "AA:BB:CC:DD:EE:FF");
            String rawSSID = (String) XposedHelpers.callMethod(prefs, "getString", "fake_ssid", "\"MyHomeWiFi\"");
            // 去掉引号
            fakeSSID = rawSSID.replace("\"", "");

            writeLog("Config loaded: en=" + enabled + " b=" + fakeBSSID + " m=" + fakeMAC + " s=" + fakeSSID);
            XposedBridge.log(TAG + ": config → en=" + enabled + " b=" + fakeBSSID + " m=" + fakeMAC + " s=" + fakeSSID);
        } catch (Throwable t) {
            writeLog("Config load FAILED: " + t.getMessage());
            XposedBridge.log(TAG + ": loadConfig failed, use defaults");
        }
    }

    // 写日志到文件
    private void writeLog(String msg) {
        try {
            File f = new File(LOG_FILE);
            PrintWriter pw = new PrintWriter(new FileWriter(f, true));
            pw.println(System.currentTimeMillis() + " " + msg);
            pw.flush();
            pw.close();
        } catch (Exception e) {
            // 忽略
        }
    }
}
