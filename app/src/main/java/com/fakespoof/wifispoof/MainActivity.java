package com.fakespoof.wifispoof;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public class MainActivity extends Activity {
    private EditText etBSSID, etMAC, etSSID;
    private EditText etIP, etGateway, etNetmask, etDNS1, etDNS2;
    private Switch switchEnabled;
    private TextView tvStatus;
    private SpoofConfig config;
    private static final String LOG_FILE = "/sdcard/wifispoof_hook.log";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        config = new SpoofConfig(this);

        // WiFi 配置
        etBSSID = findViewById(R.id.et_bssid);
        etMAC = findViewById(R.id.et_mac);
        etSSID = findViewById(R.id.et_ssid);

        // IP 配置
        etIP = findViewById(R.id.et_ip);
        etGateway = findViewById(R.id.et_gateway);
        etNetmask = findViewById(R.id.et_netmask);
        etDNS1 = findViewById(R.id.et_dns1);
        etDNS2 = findViewById(R.id.et_dns2);

        switchEnabled = findViewById(R.id.switch_enabled);
        tvStatus = findViewById(R.id.tv_status);
        Button btnSave = findViewById(R.id.btn_save);
        Button btnRandom = findViewById(R.id.btn_random);
        Button btnDetect = findViewById(R.id.btn_detect);
        Button btnLog = findViewById(R.id.btn_log);

        loadConfig();

        btnSave.setOnClickListener(v -> saveConfig());
        btnRandom.setOnClickListener(v -> generateRandom());
        btnDetect.setOnClickListener(v -> {
            Intent intent = new Intent(this, DetectorActivity.class);
            startActivity(intent);
        });
        btnLog.setOnClickListener(v -> showHookLog());
    }

    private void loadConfig() {
        // WiFi 配置
        etBSSID.setText(config.getFakeBSSID());
        etMAC.setText(config.getFakeMAC());
        etSSID.setText(config.getFakeSSID().replace("\"", ""));

        // IP 配置
        etIP.setText(config.getFakeIP());
        etGateway.setText(config.getFakeGateway());
        etNetmask.setText(config.getFakeNetmask());
        etDNS1.setText(config.getFakeDNS1());
        etDNS2.setText(config.getFakeDNS2());

        switchEnabled.setChecked(config.isEnabled());
        updateStatus();
    }

    private void saveConfig() {
        // 验证 WiFi 配置
        String bssid = etBSSID.getText().toString().trim();
        String mac = etMAC.getText().toString().trim();
        String ssid = "\"" + etSSID.getText().toString().trim() + "\"";

        if (!isValidMac(bssid)) {
            Toast.makeText(this, "BSSID格式不对 (AA:BB:CC:DD:EE:FF)", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!isValidMac(mac)) {
            Toast.makeText(this, "MAC格式不对 (AA:BB:CC:DD:EE:FF)", Toast.LENGTH_SHORT).show();
            return;
        }

        // 验证 IP 配置
        String ip = etIP.getText().toString().trim();
        String gateway = etGateway.getText().toString().trim();
        String netmask = etNetmask.getText().toString().trim();
        String dns1 = etDNS1.getText().toString().trim();
        String dns2 = etDNS2.getText().toString().trim();

        if (!isValidIP(ip)) {
            Toast.makeText(this, "IP地址格式不对 (192.168.1.100)", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!isValidIP(gateway)) {
            Toast.makeText(this, "网关格式不对 (192.168.1.1)", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!isValidIP(netmask)) {
            Toast.makeText(this, "子网掩码格式不对 (255.255.255.0)", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!isValidIP(dns1)) {
            Toast.makeText(this, "DNS1格式不对 (8.8.8.8)", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!isValidIP(dns2)) {
            Toast.makeText(this, "DNS2格式不对 (8.8.4.4)", Toast.LENGTH_SHORT).show();
            return;
        }

        // 保存配置
        config.setFakeBSSID(bssid);
        config.setFakeMAC(mac);
        config.setFakeSSID(ssid);
        config.setFakeIP(ip);
        config.setFakeGateway(gateway);
        config.setFakeNetmask(netmask);
        config.setFakeDNS1(dns1);
        config.setFakeDNS2(dns2);
        config.setEnabled(switchEnabled.isChecked());

        updateStatus();
        Toast.makeText(this, "已保存，请重启目标应用", Toast.LENGTH_SHORT).show();
    }

    private void generateRandom() {
        // 生成随机 MAC
        String r = String.format("%02X:%02X:%02X:%02X:%02X:%02X",
            (int)(Math.random()*256),(int)(Math.random()*256),(int)(Math.random()*256),
            (int)(Math.random()*256),(int)(Math.random()*256),(int)(Math.random()*256));
        etBSSID.setText(r);
        etMAC.setText(r);
        etSSID.setText("WiFi_"+(int)(Math.random()*9999));

        // 生成随机 IP (192.168.x.x 网段)
        int subnet = (int)(Math.random()*254) + 1;
        int host = (int)(Math.random()*254) + 1;
        etIP.setText("192.168." + subnet + "." + host);
        etGateway.setText("192.168." + subnet + ".1");
        etNetmask.setText("255.255.255.0");
        etDNS1.setText("8.8.8.8");
        etDNS2.setText("8.8.4.4");
    }

    private boolean isValidMac(String mac) {
        return mac != null && mac.matches("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    }

    private boolean isValidIP(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private void updateStatus() {
        if (config.isEnabled()) {
            tvStatus.setText("已启用\n" +
                "BSSID: " + config.getFakeBSSID() + "\n" +
                "MAC: " + config.getFakeMAC() + "\n" +
                "SSID: " + config.getFakeSSID() + "\n" +
                "IP: " + config.getFakeIP() + "\n" +
                "网关: " + config.getFakeGateway() + "\n" +
                "DNS: " + config.getFakeDNS1() + ", " + config.getFakeDNS2());
            tvStatus.setTextColor(0xFF4CAF50);
        } else {
            tvStatus.setText("已禁用");
            tvStatus.setTextColor(0xFFF44336);
        }
    }

    private void showHookLog() {
        try {
            File f = new File(LOG_FILE);
            if (!f.exists()) {
                new AlertDialog.Builder(this)
                    .setTitle("Hook日志")
                    .setMessage("日志文件不存在。\n\n请先：\n1. 启用模块\n2. 重启目标App\n3. 打开目标App触发hook")
                    .setPositiveButton("确定", null)
                    .show();
                return;
            }

            BufferedReader reader = new BufferedReader(new FileReader(f));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            reader.close();

            String logContent = sb.toString();
            if (logContent.isEmpty()) {
                logContent = "日志为空";
            }

            ScrollView scrollView = new ScrollView(this);
            TextView logView = new TextView(this);
            logView.setText(logContent);
            logView.setTextSize(12);
            logView.setPadding(24, 24, 24, 24);
            logView.setTextColor(0xFF00FF00);
            logView.setTypeface(android.graphics.Typeface.MONOSPACE);
            scrollView.addView(logView);

            new AlertDialog.Builder(this)
                .setTitle("Hook日志 (" + f.length() + " bytes)")
                .setView(scrollView)
                .setPositiveButton("关闭", null)
                .setNeutralButton("清空日志", (d, w) -> {
                    f.delete();
                    Toast.makeText(this, "日志已清空", Toast.LENGTH_SHORT).show();
                })
                .show();
        } catch (Exception e) {
            Toast.makeText(this, "读取日志失败: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }
}
