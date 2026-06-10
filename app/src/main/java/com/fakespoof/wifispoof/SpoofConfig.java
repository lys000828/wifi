package com.fakespoof.wifispoof;

import android.content.Context;
import android.content.SharedPreferences;

public class SpoofConfig {
    private static final String PREF_NAME = "wifi_spoof_config";
    private static final String KEY_BSSID = "fake_bssid";
    private static final String KEY_MAC = "fake_mac";
    private static final String KEY_SSID = "fake_ssid";
    private static final String KEY_ENABLED = "spoof_enabled";
    private final SharedPreferences prefs;

    public SpoofConfig(Context context) {
        prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
    }

    public boolean isEnabled() { return prefs.getBoolean(KEY_ENABLED, true); }
    public void setEnabled(boolean enabled) { prefs.edit().putBoolean(KEY_ENABLED, enabled).apply(); }
    public String getFakeBSSID() { return prefs.getString(KEY_BSSID, "AA:BB:CC:DD:EE:FF"); }
    public void setFakeBSSID(String bssid) { prefs.edit().putString(KEY_BSSID, bssid).apply(); }
    public String getFakeMAC() { return prefs.getString(KEY_MAC, "AA:BB:CC:DD:EE:FF"); }
    public void setFakeMAC(String mac) { prefs.edit().putString(KEY_MAC, mac).apply(); }
    public String getFakeSSID() { return prefs.getString(KEY_SSID, "\"MyHomeWiFi\""); }
    public void setFakeSSID(String ssid) { prefs.edit().putString(KEY_SSID, ssid).apply(); }
}
