package com.fakespoof.wifispoof;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.TransportInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WifiDetector {
    private static final String TAG = "WifiDetector";
    private final Context context;
    private final WifiManager wifiManager;
    private final ConnectivityManager connectivityManager;

    // Android 10+ 占位MAC前缀
    private static final String PLACEHOLDER_MAC_PREFIX = "02:00:00:00:00";
    private static final String PLACEHOLDER_BSSID = "02:00:00:00:00:00";
    private static final String UNKNOWN_SSID = "<unknown ssid>";

    // 检测结果摘要
    private DetectionSummary summary;

    public WifiDetector(Context context) {
        this.context = context;
        this.wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        this.connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        this.summary = new DetectionSummary();
    }

    // 1. App层API调用 - 通过WifiManager API获取
    public WifiInfoResult getAppLayerInfo() {
        WifiInfoResult result = new WifiInfoResult();
        result.source = "App层API (WifiManager)";

        try {
            WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            if (wifiInfo == null) {
                result.error = "getConnectionInfo() 返回 null";
                return result;
            }

            result.bssid = wifiInfo.getBSSID();
            result.ssid = wifiInfo.getSSID();
            result.macAddress = wifiInfo.getMacAddress();
            result.ipAddress = intToIp(wifiInfo.getIpAddress());
            result.networkId = String.valueOf(wifiInfo.getNetworkId());
            result.rssi = String.valueOf(wifiInfo.getRssi());
            result.linkSpeed = wifiInfo.getLinkSpeed() + " Mbps";
            result.frequency = wifiInfo.getFrequency() + " MHz";

            // 标记占位值（Android 10+ 系统限制）
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                if (result.bssid != null && result.bssid.startsWith(PLACEHOLDER_MAC_PREFIX)) {
                    result.bssidNote = "⚠ 占位值 (系统限制)";
                }
                if (result.ssid != null && result.ssid.equals(UNKNOWN_SSID)) {
                    result.ssidNote = "⚠ 占位值 (系统限制)";
                }
                if (result.macAddress != null && result.macAddress.startsWith(PLACEHOLDER_MAC_PREFIX)) {
                    result.macNote = "⚠ 占位值 (系统限制)";
                }
                if (result.frequency != null && result.frequency.startsWith("-1")) {
                    result.frequencyNote = "⚠ 无效值 (系统限制)";
                }
            }

            result.success = true;
        } catch (Exception e) {
            result.error = e.getMessage();
            Log.e(TAG, "App层API获取失败", e);
        }
        return result;
    }

    // 2. Java层读取 - 通过NetworkInterface获取
    public WifiInfoResult getJavaLayerInfo() {
        WifiInfoResult result = new WifiInfoResult();
        result.source = "Java层 (NetworkInterface)";

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) {
                result.error = "getNetworkInterfaces() 返回 null (权限不足或无网络接口)";
                result.success = false;
                return result;
            }

            boolean found = false;
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (ni == null) continue;

                String name = ni.getName();
                if (name != null && name.equals("wlan0")) {
                    found = true;
                    result.interfaceName = name;
                    result.interfaceDisplayName = ni.getDisplayName();

                    try {
                        byte[] mac = ni.getHardwareAddress();
                        if (mac != null) {
                            result.macAddress = formatMac(mac);
                        }
                    } catch (Exception e) {
                        Log.w(TAG, "获取MAC地址失败", e);
                    }

                    try {
                        Enumeration<InetAddress> addresses = ni.getInetAddresses();
                        if (addresses != null) {
                            while (addresses.hasMoreElements()) {
                                InetAddress addr = addresses.nextElement();
                                if (addr != null && !addr.isLoopbackAddress()) {
                                    String hostAddr = addr.getHostAddress();
                                    if (hostAddr != null) {
                                        if (hostAddr.contains(":")) {
                                            result.ipv6Address = hostAddr;
                                        } else {
                                            result.ipAddress = hostAddr;
                                        }
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        Log.w(TAG, "获取IP地址失败", e);
                    }

                    try {
                        result.isUp = String.valueOf(ni.isUp());
                        result.isLoopback = String.valueOf(ni.isLoopback());
                        result.mtu = String.valueOf(ni.getMTU());
                    } catch (Exception e) {
                        Log.w(TAG, "获取接口状态失败", e);
                    }
                    break;
                }
            }

            if (!found) {
                List<String> interfaceNames = new ArrayList<>();
                interfaces = NetworkInterface.getNetworkInterfaces();
                if (interfaces != null) {
                    while (interfaces.hasMoreElements()) {
                        NetworkInterface ni = interfaces.nextElement();
                        if (ni != null && ni.getName() != null) {
                            interfaceNames.add(ni.getName());
                        }
                    }
                }
                result.error = "未找到 wlan0 接口 (可用接口: " + String.join(", ", interfaceNames) + ")";
                result.success = false;
            } else {
                result.success = true;
            }
        } catch (Exception e) {
            result.error = e.getMessage();
            Log.e(TAG, "Java层获取失败", e);
        }
        return result;
    }

    // 3. 系统属性读取
    public WifiInfoResult getSystemPropertyInfo() {
        WifiInfoResult result = new WifiInfoResult();
        result.source = "系统属性 (System Properties)";

        try {
            result.wlanDriverVersion = getSystemProp("wlan.driver.version");
            result.wlanInterface = getSystemProp("wifi.interface");
            result.wlanChipsetName = getSystemProp("ro.hardware.wifi");
            result.ethernetInterfaces = getSystemProp("ethernet.interfaces");
            result.wifiDirectInterface = getSystemProp("wifi.direct.interface");

            String macFromSys = readMacFromSysFs("wlan0");
            if (macFromSys != null) {
                result.macAddress = macFromSys;
            }

            result.success = true;
        } catch (Exception e) {
            result.error = e.getMessage();
            Log.e(TAG, "系统属性获取失败", e);
        }
        return result;
    }

    // 4. 底层网络信息 (DhcpInfo + NetworkCapabilities)
    public WifiInfoResult getNetworkLayerInfo() {
        WifiInfoResult result = new WifiInfoResult();
        result.source = "底层网络 (DhcpInfo)";

        try {
            DhcpInfo dhcpInfo = wifiManager.getDhcpInfo();
            if (dhcpInfo != null) {
                result.ipAddress = intToIp(dhcpInfo.ipAddress);
                result.gateway = intToIp(dhcpInfo.gateway);
                result.netmask = intToIp(dhcpInfo.netmask);
                result.dns1 = intToIp(dhcpInfo.dns1);
                result.dns2 = intToIp(dhcpInfo.dns2);
                result.serverAddress = intToIp(dhcpInfo.serverAddress);
                result.leaseDuration = dhcpInfo.leaseDuration + "s";
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network activeNetwork = connectivityManager.getActiveNetwork();
                if (activeNetwork != null) {
                    NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(activeNetwork);
                    if (caps != null) {
                        result.hasWifiTransport = String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI));
                        result.hasCellularTransport = String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
                        result.hasEthernetTransport = String.valueOf(caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));

                        // Android 11+ 通过 NetworkCapabilities 获取真实 WifiInfo
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            TransportInfo transportInfo = caps.getTransportInfo();
                            if (transportInfo instanceof WifiInfo) {
                                WifiInfo realWifiInfo = (WifiInfo) transportInfo;
                                String realBssid = realWifiInfo.getBSSID();
                                if (realBssid != null && !realBssid.equals(PLACEHOLDER_BSSID)) {
                                    result.bssid = realBssid;
                                    result.bssidNote = "✓ 真实BSSID (NetworkCapabilities)";
                                }
                                int freq = realWifiInfo.getFrequency();
                                if (freq > 0) {
                                    result.frequency = freq + " MHz";
                                    result.frequencyNote = "✓ 真实频率 (NetworkCapabilities)";
                                }
                                int speed = realWifiInfo.getLinkSpeed();
                                if (speed > 0) {
                                    result.linkSpeed = speed + " Mbps";
                                }
                            }
                        }
                    }
                }
            }

            result.success = true;
        } catch (Exception e) {
            result.error = e.getMessage();
            Log.e(TAG, "底层网络获取失败", e);
        }
        return result;
    }

    // 5. WiFi扫描结果交叉验证
    public WifiInfoResult getScanResultInfo() {
        WifiInfoResult result = new WifiInfoResult();
        result.source = "WiFi扫描 (ScanResults)";

        try {
            List<ScanResult> scanResults = wifiManager.getScanResults();
            if (scanResults != null && !scanResults.isEmpty()) {
                List<String> scannedBSSIDs = new ArrayList<>();
                List<String> scannedSSIDs = new ArrayList<>();

                WifiInfo currentConnection = wifiManager.getConnectionInfo();
                String currentBSSID = currentConnection != null ? currentConnection.getBSSID() : null;
                String currentSSID = currentConnection != null ? currentConnection.getSSID() : null;
                int currentRSSI = currentConnection != null ? currentConnection.getRssi() : -127;

                // 策略1: 尝试通过 BSSID 匹配（仅在 BSSID 非占位值时有效）
                boolean matched = false;
                if (currentBSSID != null && !currentBSSID.equals(PLACEHOLDER_BSSID)
                        && !currentBSSID.startsWith(PLACEHOLDER_MAC_PREFIX)) {
                    for (ScanResult sr : scanResults) {
                        if (currentBSSID.equals(sr.BSSID)) {
                            result.bssid = sr.BSSID;
                            result.ssid = sr.SSID;
                            result.frequency = sr.frequency + " MHz";
                            result.capabilities = sr.capabilities;
                            matched = true;
                            break;
                        }
                    }
                }

                // 策略2: 通过 SSID 匹配（取信号最强的那个）
                if (!matched && currentSSID != null && !currentSSID.equals(UNKNOWN_SSID)) {
                    String cleanSSID = currentSSID.replace("\"", "");
                    ScanResult bestMatch = null;
                    for (ScanResult sr : scanResults) {
                        if (cleanSSID.equals(sr.SSID)) {
                            if (bestMatch == null || sr.level > bestMatch.level) {
                                bestMatch = sr;
                            }
                        }
                    }
                    if (bestMatch != null) {
                        result.bssid = bestMatch.BSSID;
                        result.ssid = bestMatch.SSID;
                        result.frequency = bestMatch.frequency + " MHz";
                        result.capabilities = bestMatch.capabilities;
                        matched = true;
                        result.bssidNote = "✓ 通过SSID匹配 (信号最强)";
                    }
                }

                // 策略3: 如果 RSSI 有效，取信号最强的AP作为候选
                if (!matched && currentRSSI > -127) {
                    ScanResult strongest = null;
                    for (ScanResult sr : scanResults) {
                        if (sr.level > -127 && (strongest == null || sr.level > strongest.level)) {
                            strongest = sr;
                        }
                    }
                    if (strongest != null) {
                        result.bssid = strongest.BSSID;
                        result.ssid = strongest.SSID;
                        result.frequency = strongest.frequency + " MHz";
                        result.capabilities = strongest.capabilities;
                        result.bssidNote = "⚠ 候选AP (信号最强, 未验证匹配)";
                    }
                }

                result.scannedAPCount = String.valueOf(scanResults.size());

                // 收集扫描到的AP列表
                for (ScanResult sr : scanResults) {
                    scannedBSSIDs.add(sr.BSSID);
                    scannedSSIDs.add(sr.SSID != null ? sr.SSID : "<hidden>");
                }
                result.scannedBSSIDs = scannedBSSIDs;
                result.scannedSSIDs = scannedSSIDs;

                // 验证
                if (currentBSSID != null) {
                    result.bssidInScanList = String.valueOf(scannedBSSIDs.contains(currentBSSID));
                }
            } else {
                result.scannedAPCount = "0 (扫描结果为空)";
                result.error = "未获取到扫描结果，请检查定位权限是否开启";
            }

            result.success = true;
        } catch (Exception e) {
            result.error = e.getMessage();
            Log.e(TAG, "WiFi扫描获取失败", e);
        }
        return result;
    }

    // 触发WiFi扫描
    public boolean startScan() {
        try {
            return wifiManager.startScan();
        } catch (Exception e) {
            Log.e(TAG, "触发扫描失败", e);
            return false;
        }
    }

    // 获取所有检测结果
    public List<WifiInfoResult> getAllResults() {
        List<WifiInfoResult> results = new ArrayList<>();
        WifiInfoResult appLayer = getAppLayerInfo();
        WifiInfoResult javaLayer = getJavaLayerInfo();
        WifiInfoResult sysProp = getSystemPropertyInfo();
        WifiInfoResult networkLayer = getNetworkLayerInfo();
        WifiInfoResult scanResult = getScanResultInfo();

        results.add(appLayer);
        results.add(javaLayer);
        results.add(sysProp);
        results.add(networkLayer);
        results.add(scanResult);

        // 执行交叉验证检测
        performCrossValidation(appLayer, javaLayer, sysProp, networkLayer, scanResult);

        return results;
    }

    // 获取所有检测结果（带强制扫描）
    public List<WifiInfoResult> getAllResultsWithScan() {
        startScan();
        try {
            Thread.sleep(800);
        } catch (InterruptedException e) {
            // ignore
        }
        return getAllResults();
    }

    // 获取检测摘要
    public DetectionSummary getSummary() {
        return summary;
    }

    // ========== 交叉验证检测逻辑 ==========

    private void performCrossValidation(WifiInfoResult appLayer, WifiInfoResult javaLayer,
                                       WifiInfoResult sysProp, WifiInfoResult networkLayer,
                                       WifiInfoResult scanResult) {
        summary = new DetectionSummary();

        // 1. 检测MAC地址不一致
        detectMACInconsistency(appLayer, javaLayer, sysProp);

        // 2. 检测BSSID不一致
        detectBSSIDInconsistency(appLayer, scanResult, networkLayer);

        // 3. 检测频率不一致
        detectFrequencyInconsistency(appLayer, scanResult);

        // 4. 检测SSID不一致
        detectSSIDInconsistency(appLayer, scanResult);

        // 5. 检测占位值
        detectPlaceholderValues(appLayer);

        // 6. 检测子网掩码异常
        detectSubnetMaskAnomaly(networkLayer);

        // 7. 检测系统属性MAC暴露
        detectSysfsMACExposure(sysProp);
    }

    // 检测MAC地址不一致
    private void detectMACInconsistency(WifiInfoResult appLayer, WifiInfoResult javaLayer,
                                       WifiInfoResult sysProp) {
        String appMAC = normalizeMAC(appLayer.macAddress);
        String javaMAC = normalizeMAC(javaLayer.macAddress);
        String sysMAC = normalizeMAC(sysProp.macAddress);

        // App层API返回的是占位值
        if (appMAC != null && appMAC.startsWith("020000")) {
            summary.addFinding("MAC占位值",
                "App层API返回占位MAC: " + appLayer.macAddress,
                "正常 - Android 10+ 系统限制",
                FindingLevel.INFO);
        }

        // 系统属性暴露真实MAC
        if (sysMAC != null && !sysMAC.startsWith("020000") && !sysMAC.equals("000000000000")) {
            summary.addFinding("真实MAC暴露",
                "系统属性/sysfs暴露真实MAC: " + sysProp.macAddress,
                "可通过读取 /sys/class/net/wlan0/address 获取真实MAC",
                FindingLevel.WARNING);
        }

        // Java层MAC与系统属性MAC不一致
        if (javaMAC != null && sysMAC != null && !javaMAC.equals(sysMAC)
                && !javaMAC.startsWith("020000") && !sysMAC.startsWith("020000")) {
            summary.addFinding("MAC层间不一致",
                "Java层MAC(" + javaLayer.macAddress + ") ≠ 系统属性MAC(" + sysProp.macAddress + ")",
                "可能存在MAC伪造",
                FindingLevel.SUSPICIOUS);
        }
    }

    // 检测BSSID不一致
    private void detectBSSIDInconsistency(WifiInfoResult appLayer, WifiInfoResult scanResult,
                                         WifiInfoResult networkLayer) {
        String appBSSID = normalizeMAC(appLayer.bssid);
        String scanBSSID = normalizeMAC(scanResult.bssid);
        String networkBSSID = normalizeMAC(networkLayer.bssid);

        // App层BSSID是占位值，但扫描结果有真实BSSID
        if (appBSSID != null && appBSSID.startsWith("020000")
                && scanBSSID != null && !scanBSSID.startsWith("020000")) {
            summary.addFinding("BSSID不一致",
                "App层BSSID是占位值(" + appLayer.bssid + ")，但扫描结果有真实BSSID(" + scanResult.bssid + ")",
                "可从扫描结果获取真实BSSID",
                FindingLevel.WARNING);
        }

        // NetworkCapabilities获取的BSSID与扫描结果不一致
        if (networkBSSID != null && scanBSSID != null && !networkBSSID.equals(scanBSSID)) {
            summary.addFinding("BSSID来源不一致",
                "NetworkCapabilities BSSID(" + networkLayer.bssid + ") ≠ 扫描结果 BSSID(" + scanResult.bssid + ")",
                "可能存在BSSID伪造",
                FindingLevel.SUSPICIOUS);
        }
    }

    // 检测频率不一致
    private void detectFrequencyInconsistency(WifiInfoResult appLayer, WifiInfoResult scanResult) {
        String appFreq = appLayer.frequency;
        String scanFreq = scanResult.frequency;

        if (appFreq != null && appFreq.startsWith("-1")) {
            summary.addFinding("频率无效值",
                "App层频率为 -1 MHz (无效值)",
                "系统限制，但可通过NetworkCapabilities或ScanResult获取真实频率",
                FindingLevel.INFO);

            if (scanFreq != null && !scanFreq.startsWith("-1")) {
                summary.addFinding("真实频率可获取",
                "扫描结果频率为 " + scanFreq + "，可绕过App层限制",
                "建议Hook getFrequency()返回真实值",
                FindingLevel.WARNING);
            }
        }
    }

    // 检测SSID不一致
    private void detectSSIDInconsistency(WifiInfoResult appLayer, WifiInfoResult scanResult) {
        String appSSID = appLayer.ssid;
        String scanSSID = scanResult.ssid;

        if (appSSID != null && scanSSID != null) {
            // 去除引号后比较
            String cleanAppSSID = appSSID.replace("\"", "").replace("\"", "");
            String cleanScanSSID = scanSSID.replace("\"", "");

            if (!cleanAppSSID.equals(cleanScanSSID)) {
                summary.addFinding("SSID不一致",
                    "App层SSID(\"" + cleanAppSSID + "\") ≠ 扫描SSID(\"" + cleanScanSSID + "\")",
                    "可能存在SSID伪造",
                    FindingLevel.SUSPICIOUS);
            }

            // 检测SSID格式异常（多重引号）
            if (appSSID.contains("\"\"\"")) {
                summary.addFinding("SSID格式异常",
                    "App层SSID包含多重引号: " + appSSID,
                    "可能是Hook不完整导致",
                    FindingLevel.WARNING);
            }
        }
    }

    // 检测占位值
    private void detectPlaceholderValues(WifiInfoResult appLayer) {
        int placeholderCount = 0;

        if (appLayer.bssid != null && appLayer.bssid.startsWith(PLACEHOLDER_MAC_PREFIX)) {
            placeholderCount++;
        }
        if (appLayer.macAddress != null && appLayer.macAddress.startsWith(PLACEHOLDER_MAC_PREFIX)) {
            placeholderCount++;
        }
        if (appLayer.frequency != null && appLayer.frequency.startsWith("-1")) {
            placeholderCount++;
        }

        if (placeholderCount > 0) {
            summary.addFinding("系统限制",
                "检测到 " + placeholderCount + " 个系统占位值",
                "Android 10+ 限制应用获取真实WiFi信息",
                FindingLevel.INFO);
        }
    }

    // 检测子网掩码异常
    private void detectSubnetMaskAnomaly(WifiInfoResult networkLayer) {
        if (networkLayer.netmask != null && networkLayer.netmask.equals("0.0.0.0")) {
            summary.addFinding("子网掩码异常",
                "DhcpInfo子网掩码为 0.0.0.0",
                "可能是系统Bug或伪造不完整",
                FindingLevel.WARNING);
        }
    }

    // 检测系统属性MAC暴露
    private void detectSysfsMACExposure(WifiInfoResult sysProp) {
        if (sysProp.macAddress != null && !sysProp.macAddress.equals("N/A")
                && !sysProp.macAddress.startsWith("02:00:00")) {
            summary.addFinding("MAC地址可获取",
                "通过sysfs可获取MAC: " + sysProp.macAddress,
                "需要Hook文件读取来伪造",
                FindingLevel.WARNING);
        }
    }

    // 辅助方法
    private String intToIp(int ip) {
        return (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
    }

    private String formatMac(byte[] mac) {
        if (mac == null) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X", mac[i]));
            if (i < mac.length - 1) sb.append(":");
        }
        return sb.toString();
    }

    private String normalizeMAC(String mac) {
        if (mac == null || mac.equals("N/A") || mac.isEmpty()) return null;
        return mac.replaceAll("[:\\-]", "").toLowerCase();
    }

    private String getSystemProp(String key) {
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            java.lang.reflect.Method method = clazz.getMethod("get", String.class);
            return (String) method.invoke(null, key);
        } catch (Exception e) {
            return "N/A";
        }
    }

    private String readMacFromSysFs(String interfaceName) {
        try {
            File file = new File("/sys/class/net/" + interfaceName + "/address");
            if (file.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(file));
                String mac = reader.readLine();
                reader.close();
                return mac != null ? mac.trim().toUpperCase() : null;
            }
        } catch (Exception e) {
            Log.e(TAG, "读取sysfs MAC失败", e);
        }
        return null;
    }

    // ========== 检测结果数据类 ==========

    public static class WifiInfoResult {
        public String source;
        public boolean success;
        public String error;

        // 通用字段
        public String bssid;
        public String ssid;
        public String macAddress;
        public String ipAddress;
        public String ipv6Address;
        public String networkId;
        public String rssi;
        public String linkSpeed;
        public String frequency;
        public String capabilities;

        // 备注字段（标记占位值或真实值）
        public String bssidNote;
        public String ssidNote;
        public String macNote;
        public String frequencyNote;

        // 接口信息
        public String interfaceName;
        public String interfaceDisplayName;
        public String isUp;
        public String isLoopback;
        public String mtu;

        // 系统属性
        public String wlanDriverVersion;
        public String wlanInterface;
        public String wlanChipsetName;
        public String ethernetInterfaces;
        public String wifiDirectInterface;

        // 网络信息
        public String gateway;
        public String netmask;
        public String dns1;
        public String dns2;
        public String serverAddress;
        public String leaseDuration;
        public String hasWifiTransport;
        public String hasCellularTransport;
        public String hasEthernetTransport;

        // 扫描信息
        public String scannedAPCount;
        public List<String> scannedBSSIDs;
        public List<String> scannedSSIDs;
        public String bssidInScanList;
    }

    // ========== 检测摘要相关 ==========

    public static class DetectionSummary {
        private final List<DetectionFinding> findings = new ArrayList<>();

        public void addFinding(String title, String detail, String suggestion, FindingLevel level) {
            findings.add(new DetectionFinding(title, detail, suggestion, level));
        }

        public List<DetectionFinding> getFindings() {
            return findings;
        }

        public int getWarningCount() {
            int count = 0;
            for (DetectionFinding f : findings) {
                if (f.level == FindingLevel.WARNING || f.level == FindingLevel.SUSPICIOUS) count++;
            }
            return count;
        }

        public boolean hasIssues() {
            return getWarningCount() > 0;
        }

        public String getOverallAssessment() {
            if (findings.isEmpty()) return "未检测到明显异常";
            int warnings = getWarningCount();
            if (warnings == 0) return "检测通过 - 仅有信息提示";
            if (warnings <= 2) return "存在 " + warnings + " 个潜在风险点";
            return "存在 " + warnings + " 个风险点，建议检查伪造配置";
        }
    }

    public static class DetectionFinding {
        public final String title;
        public final String detail;
        public final String suggestion;
        public final FindingLevel level;

        public DetectionFinding(String title, String detail, String suggestion, FindingLevel level) {
            this.title = title;
            this.detail = detail;
            this.suggestion = suggestion;
            this.level = level;
        }
    }

    public enum FindingLevel {
        INFO,       // 信息提示
        WARNING,    // 警告
        SUSPICIOUS  // 可疑
    }
}
