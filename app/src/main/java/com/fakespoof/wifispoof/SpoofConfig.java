package com.fakespoof.wifispoof;

import android.content.Context;
import android.content.SharedPreferences;

public class SpoofConfig {
    private static final String PREF_NAME = "wifi_spoof_config";

    // WiFi 配置
    private static final String KEY_ENABLED = "spoof_enabled";
    private static final String KEY_BSSID = "fake_bssid";
    private static final String KEY_MAC = "fake_mac";
    private static final String KEY_SSID = "fake_ssid";

    // IP 配置
    private static final String KEY_IP = "fake_ip";
    private static final String KEY_GATEWAY = "fake_gateway";
    private static final String KEY_NETMASK = "fake_netmask";
    private static final String KEY_DNS1 = "fake_dns1";
    private static final String KEY_DNS2 = "fake_dns2";

    // 网络参数
    private static final String KEY_FREQUENCY = "fake_frequency";
    private static final String KEY_LINK_SPEED = "fake_link_speed";
    private static final String KEY_RSSI = "fake_rssi";

    private final SharedPreferences prefs;

    @SuppressWarnings("deprecation")
    public SpoofConfig(Context context) {
        // MODE_WORLD_READABLE 让 XSharedPreferences 能从其他进程读取
        prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_WORLD_READABLE);
    }

    // ========== 启用/禁用 ==========
    public boolean isEnabled() { return prefs.getBoolean(KEY_ENABLED, true); }
    public void setEnabled(boolean enabled) { prefs.edit().putBoolean(KEY_ENABLED, enabled).commit(); }

    // ========== WiFi 配置 ==========
    public String getFakeBSSID() { return prefs.getString(KEY_BSSID, "AA:BB:CC:DD:EE:FF"); }
    public void setFakeBSSID(String bssid) { prefs.edit().putString(KEY_BSSID, bssid).commit(); }

    public String getFakeMAC() { return prefs.getString(KEY_MAC, "AA:BB:CC:DD:EE:FF"); }
    public void setFakeMAC(String mac) { prefs.edit().putString(KEY_MAC, mac).commit(); }

    public String getFakeSSID() { return prefs.getString(KEY_SSID, "\"MyHomeWiFi\""); }
    public void setFakeSSID(String ssid) { prefs.edit().putString(KEY_SSID, ssid).commit(); }

    // ========== IP 配置 ==========
    public String getFakeIP() { return prefs.getString(KEY_IP, "192.168.1.100"); }
    public void setFakeIP(String ip) { prefs.edit().putString(KEY_IP, ip).commit(); }

    public String getFakeGateway() { return prefs.getString(KEY_GATEWAY, "192.168.1.1"); }
    public void setFakeGateway(String gateway) { prefs.edit().putString(KEY_GATEWAY, gateway).commit(); }

    public String getFakeNetmask() { return prefs.getString(KEY_NETMASK, "255.255.255.0"); }
    public void setFakeNetmask(String netmask) { prefs.edit().putString(KEY_NETMASK, netmask).commit(); }

    public String getFakeDNS1() { return prefs.getString(KEY_DNS1, "8.8.8.8"); }
    public void setFakeDNS1(String dns1) { prefs.edit().putString(KEY_DNS1, dns1).commit(); }

    public String getFakeDNS2() { return prefs.getString(KEY_DNS2, "8.8.4.4"); }
    public void setFakeDNS2(String dns2) { prefs.edit().putString(KEY_DNS2, dns2).commit(); }

    // ========== 网络参数 ==========
    public int getFakeFrequency() { return prefs.getInt(KEY_FREQUENCY, 5180); }
    public void setFakeFrequency(int frequency) { prefs.edit().putInt(KEY_FREQUENCY, frequency).commit(); }

    public int getFakeLinkSpeed() { return prefs.getInt(KEY_LINK_SPEED, 72); }
    public void setFakeLinkSpeed(int linkSpeed) { prefs.edit().putInt(KEY_LINK_SPEED, linkSpeed).commit(); }

    public int getFakeRSSI() { return prefs.getInt(KEY_RSSI, -45); }
    public void setFakeRSSI(int rssi) { prefs.edit().putInt(KEY_RSSI, rssi).commit(); }
}
