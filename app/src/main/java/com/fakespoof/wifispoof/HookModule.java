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

    // 伪造网络参数 - 从SharedPreferences读取
    private String fakeIP = "192.168.1.100";
    private String fakeGateway = "192.168.1.1";
    private String fakeNetmask = "255.255.255.0";
    private String fakeDNS1 = "8.8.8.8";
    private String fakeDNS2 = "8.8.4.4";
    private int fakeFrequency = 5180;
    private int fakeLinkSpeed = 72;
    private int fakeRSSI = -45;
    private int fakeNetworkId = 1;

    // 日志文件路径
    private static final String LOG_FILE = "/sdcard/wifispoof_hook.log";

    // 系统进程列表 - hook这些会导致网络问题
    private static final String[] SYSTEM_PACKAGES = {
        "android",
        "com.android.wifi",
        "com.android.systemui",
        "com.android.settings",
        "com.android.providers.settings",
        "com.android.providers.media",
        "com.android.providers.downloads",
        "system_server",
        "com.android.server",
        "com.android.phone",
        "com.android.bluetooth",
        "com.android.nfc",
        "com.android.shell",
        "com.android.emergency"
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName.equals(PKG_SELF)) return;

        // 清空旧日志
        writeLog("=== WifiSpoof Hook Log ===");
        writeLog("Package: " + lpparam.packageName);
        writeLog("Time: " + System.currentTimeMillis());

        // 检查是否是系统进程 - 如果是则跳过，避免影响系统功能
        if (isSystemPackage(lpparam.packageName)) {
            writeLog("⚠️ SKIP system package: " + lpparam.packageName);
            XposedBridge.log(TAG + ": SKIP system package " + lpparam.packageName + " (may cause network issues)");
            return;
        }

        loadConfig(lpparam.classLoader, lpparam.packageName);
        if (!enabled) {
            writeLog("STATUS: DISABLED, skip " + lpparam.packageName);
            XposedBridge.log(TAG + ": disabled, skip " + lpparam.packageName);
            return;
        }

        writeLog("Config: BSSID=" + fakeBSSID + " MAC=" + fakeMAC + " SSID=" + fakeSSID);
        writeLog("Config: IP=" + fakeIP + " GW=" + fakeGateway + " DNS=" + fakeDNS1 + "," + fakeDNS2);
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

    // 检查是否是系统进程
    private boolean isSystemPackage(String packageName) {
        if (packageName == null) return true;

        // 检查是否在系统进程列表中
        for (String sysPkg : SYSTEM_PACKAGES) {
            if (sysPkg.equals(packageName)) {
                return true;
            }
        }

        // 检查是否是 com.android.* 开头的系统进程
        if (packageName.startsWith("com.android.") && !packageName.equals("com.android.chrome")) {
            return true;
        }

        // 检查是否是系统UID (uid < 10000)
        // 注意：这个检查需要在运行时进行，这里先返回false

        return false;
    }

    // ====================================================================
    // 1. App层API - WifiManager / WifiInfo
    // ====================================================================
    private void hookAppLayer(ClassLoader cl) {
        // getConnectionInfo → 返回伪造WifiInfo
        hook("android.net.wifi.WifiManager", cl, "getConnectionInfo", p -> {
            WifiInfo fake = buildFakeWifiInfo();
            if (fake != null) {
                p.setResult(fake);
            }
            // 如果fake为null，保持原返回值，由各getter hook返回伪造值
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
            writeLog("✓ WifiInfo.getIpAddress → " + fakeIP);
        });

        // getServerAddress
        hook("android.net.wifi.WifiInfo", cl, "getServerAddress", p -> {
            p.setResult(ipToInt(fakeGateway));
            writeLog("✓ WifiInfo.getServerAddress → " + fakeGateway);
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
                    String name = ni.getName();
                    // 检查是否是WiFi相关接口
                    if (name != null && (name.equals("wlan0") || name.contains("wlan")
                            || name.contains("wifi") || name.contains("eth"))) {
                        try {
                            InetAddress fakeAddr = InetAddress.getByName(fakeIP);
                            List<InetAddress> addrs = new ArrayList<>();
                            addrs.add(fakeAddr);
                            param.setResult(java.util.Collections.enumeration(addrs));
                            writeLog("✓ getInetAddresses hooked for " + name + " → " + fakeIP);
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

        // getInterfaceAddresses → 伪造IP (Android 23+) - 使用反射创建
        try {
            findAndHookMethod(NetworkInterface.class, "getInterfaceAddresses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    NetworkInterface ni = (NetworkInterface) param.thisObject;
                    String name = ni.getName();
                    if (name != null && (name.equals("wlan0") || name.contains("wlan")
                            || name.contains("wifi") || name.contains("eth"))) {
                        try {
                            // 使用反射创建InterfaceAddress
                            Class<?> ifAddrClass = Class.forName("java.net.InterfaceAddress");
                            java.lang.reflect.Constructor<?> constructor = ifAddrClass.getDeclaredConstructor();
                            constructor.setAccessible(true);
                            Object fakeAddr = constructor.newInstance();

                            // 设置address字段
                            Field addrField = ifAddrClass.getDeclaredField("address");
                            addrField.setAccessible(true);
                            addrField.set(fakeAddr, InetAddress.getByName(fakeIP));

                            List<Object> addrs = new ArrayList<>();
                            addrs.add(fakeAddr);
                            param.setResult(addrs);
                            writeLog("✓ getInterfaceAddresses hooked for " + name + " → " + fakeIP);
                        } catch (Exception e) {
                            writeLog("✗ getInterfaceAddresses hook failed: " + e.getMessage());
                        }
                    }
                }
            });
            writeLog("✓ NetworkInterface.getInterfaceAddresses");
        } catch (Throwable t) {
            writeLog("✗ NetworkInterface.getInterfaceAddresses: " + t.getMessage());
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

        // Hook sysfs MAC文件的读取 - 多种方式拦截

        // 1. FileInputStream(File) 构造函数
        try {
            findAndHookMethod(java.io.FileInputStream.class, "<init>", java.io.File.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    File file = (File) param.args[0];
                    if (file != null) {
                        String path = file.getAbsolutePath();
                        if (path.matches(".*/sys/class/net/.*/address")) {
                            try {
                                File tmp = createFakeMacFile();
                                param.args[0] = tmp;
                                writeLog("✓ FileInputStream(File) redirected: " + path);
                            } catch (Exception e) {
                                writeLog("✗ FileInputStream(File) redirect failed: " + e.getMessage());
                            }
                        }
                    }
                }
            });
            writeLog("✓ FileInputStream.<init>(File)");
        } catch (Throwable t) {
            writeLog("✗ FileInputStream.<init>(File): " + t.getMessage());
        }

        // 2. FileInputStream(String) 构造函数 - 很多代码用字符串路径
        try {
            findAndHookMethod(java.io.FileInputStream.class, "<init>", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String path = (String) param.args[0];
                    if (path != null && path.matches(".*/sys/class/net/.*/address")) {
                        try {
                            File tmp = createFakeMacFile();
                            // 替换为File构造函数
                            param.args[0] = tmp.getAbsolutePath();
                            writeLog("✓ FileInputStream(String) redirected: " + path);
                        } catch (Exception e) {
                            writeLog("✗ FileInputStream(String) redirect failed: " + e.getMessage());
                        }
                    }
                }
            });
            writeLog("✓ FileInputStream.<init>(String)");
        } catch (Throwable t) {
            writeLog("✗ FileInputStream.<init>(String): " + t.getMessage());
        }

        // 3. FileReader(File) 构造函数
        try {
            findAndHookMethod(java.io.FileReader.class, "<init>", java.io.File.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    File file = (File) param.args[0];
                    if (file != null) {
                        String path = file.getAbsolutePath();
                        if (path.matches(".*/sys/class/net/.*/address")) {
                            try {
                                File tmp = createFakeMacFile();
                                param.args[0] = tmp;
                                writeLog("✓ FileReader(File) redirected: " + path);
                            } catch (Exception e) {
                                writeLog("✗ FileReader(File) redirect failed: " + e.getMessage());
                            }
                        }
                    }
                }
            });
            writeLog("✓ FileReader.<init>(File)");
        } catch (Throwable t) {
            writeLog("✗ FileReader.<init>(File): " + t.getMessage());
        }

        // 4. FileReader(String) 构造函数
        try {
            findAndHookMethod(java.io.FileReader.class, "<init>", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String path = (String) param.args[0];
                    if (path != null && path.matches(".*/sys/class/net/.*/address")) {
                        try {
                            File tmp = createFakeMacFile();
                            param.args[0] = tmp.getAbsolutePath();
                            writeLog("✓ FileReader(String) redirected: " + path);
                        } catch (Exception e) {
                            writeLog("✗ FileReader(String) redirect failed: " + e.getMessage());
                        }
                    }
                }
            });
            writeLog("✓ FileReader.<init>(String)");
        } catch (Throwable t) {
            writeLog("✗ FileReader.<init>(String): " + t.getMessage());
        }

        // 5. File.exists - 拦截sysfs文件存在性检查
        try {
            findAndHookMethod(java.io.File.class, "exists", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    File file = (File) param.thisObject;
                    String path = file.getAbsolutePath();
                    if (path.matches(".*/sys/class/net/.*/address")) {
                        // 确保文件"存在"
                        param.setResult(true);
                    }
                }
            });
            writeLog("✓ File.exists (sysfs)");
        } catch (Throwable t) {
            writeLog("✗ File.exists: " + t.getMessage());
        }

        // 6. File.length - 返回假MAC文件大小
        try {
            findAndHookMethod(java.io.File.class, "length", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    File file = (File) param.thisObject;
                    String path = file.getAbsolutePath();
                    if (path.matches(".*/sys/class/net/.*/address")) {
                        // 返回假MAC的字节长度
                        param.setResult((long)(fakeMAC.toLowerCase() + "\n").getBytes().length);
                    }
                }
            });
            writeLog("✓ File.length (sysfs)");
        } catch (Throwable t) {
            writeLog("✗ File.length: " + t.getMessage());
        }

        // 7. BufferedReader.readLine - 兜底方案
        try {
            findAndHookMethod(BufferedReader.class, "readLine", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    String original = (String) param.getResult();
                    if (original == null) return;
                    // 检查是否是MAC格式的行
                    String trimmed = original.trim().toLowerCase();
                    if (trimmed.matches("[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}")) {
                        // 检查调用栈，判断是否来自读取sysfs的操作
                        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                        for (StackTraceElement frame : stack) {
                            String cls = frame.getClassName();
                            String method = frame.getMethodName();
                            // 检查是否来自网络相关类
                            if (cls.contains("NetworkInterface") || cls.contains("LinuxNet")
                                || cls.contains("WifiInfo") || cls.contains("LinkProperties")
                                || cls.contains("InetAddress") || cls.contains("SocketImpl")
                                || method.contains("getHardwareAddress") || method.contains("readMac")) {
                                param.setResult(fakeMAC.toLowerCase());
                                writeLog("✓ BufferedReader.readLine intercepted MAC: " + original + " → " + fakeMAC);
                                break;
                            }
                        }
                    }
                }
            });
            writeLog("✓ BufferedReader.readLine (MAC interceptor)");
        } catch (Throwable t) {
            writeLog("✗ BufferedReader.readLine: " + t.getMessage());
        }

        // 8. Files.readAllBytes / Files.readAllLines (Java 7+ NIO)
        try {
            Class<?> filesClass = Class.forName("java.nio.file.Files");
            // readAllBytes(Path)
            findAndHookMethod(filesClass, "readAllBytes", java.nio.file.Path.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    java.nio.file.Path path = (java.nio.file.Path) param.args[0];
                    if (path != null) {
                        String pathStr = path.toString();
                        if (pathStr.matches(".*/sys/class/net/.*/address")) {
                            param.setResult((fakeMAC.toLowerCase() + "\n").getBytes());
                            writeLog("✓ Files.readAllBytes intercepted: " + pathStr);
                        }
                    }
                }
            });
            writeLog("✓ Files.readAllBytes (NIO)");
        } catch (Throwable t) {
            writeLog("✗ Files.readAllBytes: " + t.getMessage());
        }

        // 9. Files.readAllLines (Java 7+ NIO)
        try {
            Class<?> filesClass = Class.forName("java.nio.file.Files");
            findAndHookMethod(filesClass, "readAllLines", java.nio.file.Path.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    java.nio.file.Path path = (java.nio.file.Path) param.args[0];
                    if (path != null) {
                        String pathStr = path.toString();
                        if (pathStr.matches(".*/sys/class/net/.*/address")) {
                            java.util.List<String> lines = new java.util.ArrayList<>();
                            lines.add(fakeMAC.toLowerCase());
                            param.setResult(lines);
                            writeLog("✓ Files.readAllLines intercepted: " + pathStr);
                        }
                    }
                }
            });
            writeLog("✓ Files.readAllLines (NIO)");
        } catch (Throwable t) {
            writeLog("✗ Files.readAllLines: " + t.getMessage());
        }

        // 10. Scanner - 有些代码用Scanner读取文件
        try {
            findAndHookMethod(java.util.Scanner.class, "<init>", java.io.InputStream.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    // Scanner初始化后，检查是否有sysfs MAC在缓冲区
                    // 这个比较难hook，先跳过
                }
            });
            writeLog("✓ Scanner.<init> (placeholder)");
        } catch (Throwable t) {
            writeLog("✗ Scanner.<init>: " + t.getMessage());
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
                fakeDhcp.netmask = ipToInt(fakeNetmask);
                fakeDhcp.dns1 = ipToInt(fakeDNS1);
                fakeDhcp.dns2 = ipToInt(fakeDNS2);
                fakeDhcp.serverAddress = ipToInt(fakeGateway);
                fakeDhcp.leaseDuration = 86400;
                p.setResult(fakeDhcp);
                writeLog("✓ getDhcpInfo → IP=" + fakeIP + " gw=" + fakeGateway + " mask=" + fakeNetmask);
            } catch (Throwable e) {
                writeLog("✗ getDhcpInfo hook failed: " + e.getMessage());
                XposedBridge.log(TAG + ": build fake DhcpInfo failed: " + e.getMessage());
            }
        });

        // NetworkCapabilities.getTransportInfo → 返回伪造WifiInfo (Android 12+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            hook("android.net.NetworkCapabilities", cl, "getTransportInfo", p -> {
                Object result = p.getResult();
                if (result instanceof WifiInfo) {
                    WifiInfo fake = buildFakeWifiInfo();
                    if (fake != null) {
                        p.setResult(fake);
                    }
                }
            });
        }

        // hasTransport → WiFi=true (Android 6+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            hook("android.net.NetworkCapabilities", cl, "hasTransport", p -> {
                int type = (int) p.args[0];
                if (type == 0) p.setResult(true);  // TRANSPORT_WIFI
                if (type == 1) p.setResult(false); // TRANSPORT_CELLULAR
                if (type == 3) p.setResult(false); // TRANSPORT_ETHERNET
            });
            writeLog("✓ NetworkCapabilities.hasTransport");
        }

        // Android 9 适配: hook ActiveNetwork获取方式
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            hook("android.net.ConnectivityManager", cl, "getActiveNetwork", p -> {
                // 保持原返回值，但后续会通过其他hook伪造信息
            });
            writeLog("✓ ConnectivityManager.getActiveNetwork (Android 6+)");
        }

        // Android 9 适配: hook getNetworkCapabilities
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            hook("android.net.ConnectivityManager", cl, "getNetworkCapabilities", p -> {
                // 保持原返回值，NetworkCapabilities的其他方法会被hook
            });
            writeLog("✓ ConnectivityManager.getNetworkCapabilities (Android 6+)");
        }

        // ConnectivityManager.getActiveNetworkInfo → 返回伪造NetworkInfo
        try {
            hook("android.net.ConnectivityManager", cl, "getActiveNetworkInfo", p -> {
                // 让原始方法执行，后续会通过其他hook伪造信息
                writeLog("✓ ConnectivityManager.getActiveNetworkInfo called");
            });
            writeLog("✓ ConnectivityManager.getActiveNetworkInfo");
        } catch (Throwable t) {
            writeLog("✗ ConnectivityManager.getActiveNetworkInfo: " + t.getMessage());
        }

        // NetworkInfo.getExtraInfo → 返回伪造SSID
        try {
            hook("android.net.NetworkInfo", cl, "getExtraInfo", p -> {
                p.setResult("\"" + fakeSSID + "\"");
                writeLog("✓ NetworkInfo.getExtraInfo → " + fakeSSID);
            });
            writeLog("✓ NetworkInfo.getExtraInfo");
        } catch (Throwable t) {
            writeLog("✗ NetworkInfo.getExtraInfo: " + t.getMessage());
        }

        // LinkAddress.getAddress → 伪造IP (Android 7+)
        try {
            findAndHookMethod("android.net.LinkAddress", cl, "getAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        InetAddress fakeAddr = InetAddress.getByName(fakeIP);
                        param.setResult(fakeAddr);
                        writeLog("✓ LinkAddress.getAddress → " + fakeIP);
                    } catch (Exception e) {
                        writeLog("✗ LinkAddress.getAddress hook failed: " + e.getMessage());
                    }
                }
            });
            writeLog("✓ LinkAddress.getAddress");
        } catch (Throwable t) {
            writeLog("✗ LinkAddress.getAddress: " + t.getMessage());
        }

        // LinkAddress.toString → 返回伪造IP (Android 7+)
        try {
            findAndHookMethod("android.net.LinkAddress", cl, "toString", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    param.setResult(fakeIP + "/24");
                    writeLog("✓ LinkAddress.toString → " + fakeIP + "/24");
                }
            });
            writeLog("✓ LinkAddress.toString");
        } catch (Throwable t) {
            writeLog("✗ LinkAddress.toString: " + t.getMessage());
        }

        // InetAddress.getHostAddress → 伪造IP (拦截所有InetAddress)
        try {
            findAndHookMethod(InetAddress.class, "getHostAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    InetAddress addr = (InetAddress) param.thisObject;
                    String hostAddr = addr.getHostAddress();
                    // 检查是否是本地WiFi IP
                    if (hostAddr != null && hostAddr.startsWith("192.168.") ||
                        hostAddr.startsWith("10.") || hostAddr.startsWith("172.")) {
                        // 可能是WiFi IP，替换为伪造值
                        if (!hostAddr.equals(fakeIP)) {
                            param.setResult(fakeIP);
                            writeLog("✓ InetAddress.getHostAddress → " + fakeIP + " (was " + hostAddr + ")");
                        }
                    }
                }
            });
            writeLog("✓ InetAddress.getHostAddress");
        } catch (Throwable t) {
            writeLog("✗ InetAddress.getHostAddress: " + t.getMessage());
        }

        // Inet4Address.getHostAddress → 伪造IPv4
        try {
            findAndHookMethod(java.net.Inet4Address.class, "getHostAddress", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    param.setResult(fakeIP);
                    writeLog("✓ Inet4Address.getHostAddress → " + fakeIP);
                }
            });
            writeLog("✓ Inet4Address.getHostAddress");
        } catch (Throwable t) {
            writeLog("✗ Inet4Address.getHostAddress: " + t.getMessage());
        }

        // ========== LinkProperties IP Hooks (所有Android版本) ==========
        // getInterfaceName → wlan0
        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getInterfaceName",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String result = (String) param.getResult();
                        if (result != null && (result.contains("wlan") || result.contains("eth"))) {
                            param.setResult("wlan0");
                        }
                    }
                });
            writeLog("✓ LinkProperties.getInterfaceName");
        } catch (Throwable t) {
            writeLog("✗ LinkProperties.getInterfaceName: " + t.getMessage());
        }

        // getLinkAddresses → 伪造IP
        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getLinkAddresses",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            Class<?> linkAddrClass = Class.forName("android.net.LinkAddress");
                            java.lang.reflect.Constructor<?> constructor = linkAddrClass.getConstructor(
                                InetAddress.class, int.class);
                            InetAddress fakeAddr = InetAddress.getByName(fakeIP);
                            Object fakeLinkAddr = constructor.newInstance(fakeAddr, 24);

                            List<Object> newList = new ArrayList<>();
                            newList.add(fakeLinkAddr);
                            param.setResult(newList);
                            writeLog("✓ LinkProperties.getLinkAddresses → " + fakeIP);
                        } catch (Throwable e) {
                            writeLog("✗ LinkProperties.getLinkAddresses hook failed: " + e.getMessage());
                        }
                    }
                });
            writeLog("✓ LinkProperties.getLinkAddresses");
        } catch (Throwable t) {
            writeLog("✗ LinkProperties.getLinkAddresses: " + t.getMessage());
        }

        // getDhcpServerAddress → 伪造DHCP服务器
        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getDhcpServerAddress",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            InetAddress fakeServer = InetAddress.getByName(fakeGateway);
                            param.setResult(fakeServer);
                            writeLog("✓ LinkProperties.getDhcpServerAddress → " + fakeGateway);
                        } catch (Throwable e) {
                            writeLog("✗ hook failed: " + e.getMessage());
                        }
                    }
                });
            writeLog("✓ LinkProperties.getDhcpServerAddress");
        } catch (Throwable t) {
            writeLog("✗ LinkProperties.getDhcpServerAddress: " + t.getMessage());
        }

        // getDnsServers → 伪造DNS
        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getDnsServers",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            List<InetAddress> fakeDns = new ArrayList<>();
                            fakeDns.add(InetAddress.getByName(fakeDNS1));
                            fakeDns.add(InetAddress.getByName(fakeDNS2));
                            param.setResult(fakeDns);
                            writeLog("✓ LinkProperties.getDnsServers → " + fakeDNS1 + "," + fakeDNS2);
                        } catch (Throwable e) {
                            writeLog("✗ hook failed: " + e.getMessage());
                        }
                    }
                });
            writeLog("✓ LinkProperties.getDnsServers");
        } catch (Throwable t) {
            writeLog("✗ LinkProperties.getDnsServers: " + t.getMessage());
        }

        // getRoutes → 伪造路由网关
        try {
            findAndHookMethod("android.net.LinkProperties", cl, "getRoutes",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            Class<?> routeInfoClass = Class.forName("android.net.RouteInfo");
                            java.lang.reflect.Constructor<?> constructor = routeInfoClass.getConstructor(
                                java.net.InetAddress.class, java.net.InetAddress.class, String.class);
                            InetAddress fakeDest = InetAddress.getByName("0.0.0.0");
                            InetAddress fakeGatewayAddr = InetAddress.getByName(fakeGateway);
                            Object fakeRoute = constructor.newInstance(fakeDest, fakeGatewayAddr, "wlan0");

                            List<Object> newList = new ArrayList<>();
                            newList.add(fakeRoute);
                            param.setResult(newList);
                            writeLog("✓ LinkProperties.getRoutes → gateway=" + fakeGateway);
                        } catch (Throwable e) {
                            writeLog("✗ hook failed: " + e.getMessage());
                        }
                    }
                });
            writeLog("✓ LinkProperties.getRoutes");
        } catch (Throwable t) {
            writeLog("✗ LinkProperties.getRoutes: " + t.getMessage());
        }
    }

    // ====================================================================
    // 5. WiFi扫描 - getScanResults / ScanResult
    // ====================================================================
    private void hookScanResults(ClassLoader cl) {
        // getScanResults → 注入伪造AP + 伪造所有结果频率
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
                }
                // 伪造所有结果的频率，防止通过其他AP获取真实频率
                if (sr.frequency <= 0 || sr.frequency > 6000) {
                    sr.frequency = fakeFrequency;
                }
            }

            // 没有就插入伪造AP
            if (!found) {
                ScanResult fakeAP = createFakeScanResult();
                original.add(0, fakeAP);
            }

            p.setResult(original);
        });

        // ScanResult.frequency字段 - 通过getter hook
        try {
            findAndHookMethod(ScanResult.class, "getFrequency", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    ScanResult sr = (ScanResult) param.thisObject;
                    if (fakeBSSID.equalsIgnoreCase(sr.BSSID)) {
                        param.setResult(fakeFrequency);
                    }
                }
            });
            writeLog("✓ ScanResult.getFrequency");
        } catch (Throwable t) {
            writeLog("✗ ScanResult.getFrequency: " + t.getMessage());
        }

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

            // 通过反射设置字段 - 遍历所有可能的字段名
            setField(info, "mBssid", fakeBSSID);
            setField(info, "mBSSID", fakeBSSID);
            setField(info, "mMacAddress", fakeMAC);
            setField(info, "mSSID", "\"" + fakeSSID + "\"");
            setIntFieldSafe(info, "mNetworkId", fakeNetworkId);
            setIntFieldSafe(info, "mRssi", fakeRSSI);
            setIntFieldSafe(info, "mLinkSpeed", fakeLinkSpeed);
            setIntFieldSafe(info, "mFrequency", fakeFrequency);
            setIntFieldSafe(info, "mIpAddress", ipToInt(fakeIP));
            // Android 12+ 可能有不同的字段名，Android 9 可能没有这些字段
            setIntFieldSafe(info, "mWifiStandard", 4); // IEEE_802_11_AC
            setIntFieldSafe(info, "mSecurityType", 3);  // WPA2_PSK

            return info;
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": buildFakeWifiInfo failed: " + t.getMessage());
            // 失败时返回null，但各getter已单独hook，仍能返回伪造值
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

    // 安全的setIntField - 兼容所有Android版本
    private void setIntFieldSafe(Object obj, String name, int value) {
        try {
            Class<?> clazz = obj.getClass();
            while (clazz != null) {
                try {
                    Field f = clazz.getDeclaredField(name);
                    f.setAccessible(true);
                    f.setInt(obj, value);
                    return;
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
        } catch (Throwable t) {
            // 字段不存在，忽略
        }
    }

    // 创建包含假MAC的临时文件
    private File createFakeMacFile() throws Exception {
        File tmp = File.createTempFile("fake_mac_", ".tmp");
        tmp.deleteOnExit();
        FileWriter fw = new FileWriter(tmp);
        fw.write(fakeMAC.toLowerCase() + "\n");
        fw.close();
        return tmp;
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
    private void loadConfig(ClassLoader cl, String packageName) {
        XposedBridge.log(TAG + ": loadConfig START for package: " + packageName);

        // 方法1: 从外部存储配置文件读取（最可靠）
        try {
            loadConfigFromExternalFile();
            writeLog("Config loaded from external file successfully");
            XposedBridge.log(TAG + ": config loaded from external file → BSSID=" + fakeBSSID + " MAC=" + fakeMAC + " IP=" + fakeIP);
            return;
        } catch (Throwable t) {
            writeLog("External file load failed: " + t.getMessage());
            XposedBridge.log(TAG + ": External load failed: " + t.getMessage());
        }

        // 方法2: 直接读取SharedPreferences XML文件
        try {
            loadConfigFromFile();
            writeLog("Config loaded from XML file successfully");
            XposedBridge.log(TAG + ": config loaded from XML → BSSID=" + fakeBSSID + " MAC=" + fakeMAC + " IP=" + fakeIP);
            return;
        } catch (Throwable t) {
            writeLog("XML file load failed: " + t.getMessage());
            XposedBridge.log(TAG + ": XML load failed: " + t.getMessage());
        }

        // 方法3: 通过createPackageContext
        try {
            Object at = XposedHelpers.callStaticMethod(
                Class.forName("android.app.ActivityThread"), "currentActivityThread");
            Object sysCtx = XposedHelpers.callMethod(at, "getSystemContext");
            Object spoofCtx = XposedHelpers.callMethod(sysCtx, "createPackageContext",
                PKG_SELF, 2);
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

            writeLog("Config loaded via createPackageContext");
            writeLog("  WiFi: b=" + fakeBSSID + " m=" + fakeMAC + " s=" + fakeSSID);
            writeLog("  IP: " + fakeIP + " gw=" + fakeGateway);
            XposedBridge.log(TAG + ": config → BSSID=" + fakeBSSID + " IP=" + fakeIP);
        } catch (Throwable t) {
            writeLog("createPackageContext failed: " + t.getMessage());
            XposedBridge.log(TAG + ": createPackageContext failed: " + t.getMessage());
            XposedBridge.log(TAG + ": using default values");
        }
    }

    // 从外部存储配置文件读取
    private void loadConfigFromExternalFile() throws Throwable {
        // 尝试多个可能的外部存储路径
        String[] possiblePaths = {
            "/sdcard/wifi_spoof_config.txt",
            "/sdcard/Android/data/com.fakespoof.wifispoof/wifi_spoof_config.txt",
            "/storage/emulated/0/wifi_spoof_config.txt",
            "/storage/emulated/0/Android/data/com.fakespoof.wifispoof/wifi_spoof_config.txt",
            "/data/local/tmp/wifi_spoof_config.txt",
            "/sdcard/Android/data/com.fakespoof.wifispoof/files/wifi_spoof_config.txt"
        };

        File configFile = null;
        for (String path : possiblePaths) {
            File f = new File(path);
            XposedBridge.log(TAG + ": checking path: " + path + " exists=" + f.exists());
            if (f.exists() && f.length() > 0) {
                configFile = f;
                XposedBridge.log(TAG + ": FOUND config at: " + path + " size=" + f.length());
                break;
            }
        }

        if (configFile == null) {
            throw new Exception("Config file not found in any location");
        }

        XposedBridge.log(TAG + ": reading config from: " + configFile.getAbsolutePath());

        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(configFile));
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.startsWith("enabled=")) {
                enabled = "true".equals(line.substring(8));
            } else if (line.startsWith("bssid=")) {
                fakeBSSID = line.substring(6);
            } else if (line.startsWith("mac=")) {
                fakeMAC = line.substring(4);
            } else if (line.startsWith("ssid=")) {
                fakeSSID = line.substring(5).replace("\"", "");
            } else if (line.startsWith("ip=")) {
                fakeIP = line.substring(3);
            } else if (line.startsWith("gateway=")) {
                fakeGateway = line.substring(8);
            } else if (line.startsWith("netmask=")) {
                fakeNetmask = line.substring(8);
            } else if (line.startsWith("dns1=")) {
                fakeDNS1 = line.substring(5);
            } else if (line.startsWith("dns2=")) {
                fakeDNS2 = line.substring(5);
            }
        }
        reader.close();

        XposedBridge.log(TAG + ": LOADED → BSSID=" + fakeBSSID + " MAC=" + fakeMAC + " IP=" + fakeIP + " GW=" + fakeGateway);
    }

    // 直接读取SharedPreferences XML文件
    private void loadConfigFromFile() throws Throwable {
        // 尝试多个可能的路径
        String[] possiblePaths = {
            "/data/data/" + PKG_SELF + "/shared_prefs/" + PREF_NAME + ".xml",
            "/data/user/0/" + PKG_SELF + "/shared_prefs/" + PREF_NAME + ".xml",
            "/data/user_de/0/" + PKG_SELF + "/shared_prefs/" + PREF_NAME + ".xml"
        };

        File prefsFile = null;
        for (String path : possiblePaths) {
            File f = new File(path);
            XposedBridge.log(TAG + ": checking path: " + path + " exists=" + f.exists());
            if (f.exists()) {
                prefsFile = f;
                XposedBridge.log(TAG + ": FOUND config file at: " + path);
                break;
            }
        }

        if (prefsFile == null) {
            writeLog("Config file NOT FOUND in any location");
            XposedBridge.log(TAG + ": config file not found in any location");
            throw new Exception("Config file not found");
        }

        XposedBridge.log(TAG + ": reading config from: " + prefsFile.getAbsolutePath());
        XposedBridge.log(TAG + ": file size: " + prefsFile.length() + " bytes");

        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(prefsFile));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();

        String xml = sb.toString();
        XposedBridge.log(TAG + ": XML content length: " + xml.length());
        // 打印XML内容前200字符用于调试
        XposedBridge.log(TAG + ": XML preview: " + xml.substring(0, Math.min(200, xml.length())));

        // 解析配置
        enabled = parseXmlBool(xml, "spoof_enabled", true);
        fakeBSSID = parseXmlString(xml, "fake_bssid", "AA:BB:CC:DD:EE:FF");
        fakeMAC = parseXmlString(xml, "fake_mac", "AA:BB:CC:DD:EE:FF");
        String rawSSID = parseXmlString(xml, "fake_ssid", "\"MyHomeWiFi\"");
        fakeSSID = rawSSID.replace("\"", "");

        // 解析IP配置
        fakeIP = parseXmlString(xml, "fake_ip", "192.168.1.100");
        fakeGateway = parseXmlString(xml, "fake_gateway", "192.168.1.1");
        fakeNetmask = parseXmlString(xml, "fake_netmask", "255.255.255.0");
        fakeDNS1 = parseXmlString(xml, "fake_dns1", "8.8.8.8");
        fakeDNS2 = parseXmlString(xml, "fake_dns2", "8.8.4.4");

        // 解析网络参数
        fakeFrequency = parseXmlInt(xml, "fake_frequency", 5180);
        fakeLinkSpeed = parseXmlInt(xml, "fake_link_speed", 72);
        fakeRSSI = parseXmlInt(xml, "fake_rssi", -45);

        writeLog("Config loaded from file:");
        writeLog("  enabled=" + enabled);
        writeLog("  BSSID=" + fakeBSSID);
        writeLog("  MAC=" + fakeMAC);
        writeLog("  SSID=" + fakeSSID);
        writeLog("  IP=" + fakeIP);
        writeLog("  Gateway=" + fakeGateway);
        writeLog("  DNS=" + fakeDNS1 + "," + fakeDNS2);

        XposedBridge.log(TAG + ": LOADED BSSID=" + fakeBSSID + " MAC=" + fakeMAC + " IP=" + fakeIP);
    }

    // 从XML中提取字符串值
    private String parseXmlString(String xml, String key, String defaultValue) {
        try {
            // 搜索 name="key">value< 格式
            String search = "name=\"" + key + "\">";
            int start = xml.indexOf(search);
            if (start < 0) return defaultValue;
            start += search.length();
            int end = xml.indexOf("<", start);
            if (end < 0) return defaultValue;
            String val = xml.substring(start, end);
            // XML转义还原
            val = val.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'");
            return val;
        } catch (Exception e) {
            return defaultValue;
        }
    }

    // 从XML中提取布尔值
    private boolean parseXmlBool(String xml, String key, boolean defaultValue) {
        String val = parseXmlString(xml, key, String.valueOf(defaultValue));
        return "true".equals(val);
    }

    // 从XML中提取整数值
    private int parseXmlInt(String xml, String key, int defaultValue) {
        String val = parseXmlString(xml, key, String.valueOf(defaultValue));
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
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
