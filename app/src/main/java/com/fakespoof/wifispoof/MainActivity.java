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
    private Switch switchEnabled;
    private TextView tvStatus;
    private SpoofConfig config;
    private static final String LOG_FILE = "/sdcard/wifispoof_hook.log";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        config = new SpoofConfig(this);
        etBSSID = findViewById(R.id.et_bssid);
        etMAC = findViewById(R.id.et_mac);
        etSSID = findViewById(R.id.et_ssid);
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
        etBSSID.setText(config.getFakeBSSID());
        etMAC.setText(config.getFakeMAC());
        etSSID.setText(config.getFakeSSID().replace("\"", ""));
        switchEnabled.setChecked(config.isEnabled());
        updateStatus();
    }

    private void saveConfig() {
        String bssid = etBSSID.getText().toString().trim();
        String mac = etMAC.getText().toString().trim();
        String ssid = "\"" + etSSID.getText().toString().trim() + "\"";
        if (!isValidMac(bssid)) { Toast.makeText(this, "BSSID格式不对", Toast.LENGTH_SHORT).show(); return; }
        if (!isValidMac(mac)) { Toast.makeText(this, "MAC格式不对", Toast.LENGTH_SHORT).show(); return; }
        config.setFakeBSSID(bssid);
        config.setFakeMAC(mac);
        config.setFakeSSID(ssid);
        config.setEnabled(switchEnabled.isChecked());
        updateStatus();
        Toast.makeText(this, "已保存，请重启目标应用", Toast.LENGTH_SHORT).show();
    }

    private void generateRandom() {
        String r = String.format("%02X:%02X:%02X:%02X:%02X:%02X",
            (int)(Math.random()*256),(int)(Math.random()*256),(int)(Math.random()*256),
            (int)(Math.random()*256),(int)(Math.random()*256),(int)(Math.random()*256));
        etBSSID.setText(r);
        etMAC.setText(r);
        etSSID.setText("WiFi_"+(int)(Math.random()*9999));
    }

    private boolean isValidMac(String mac) {
        return mac != null && mac.matches("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    }

    private void updateStatus() {
        if (config.isEnabled()) {
            tvStatus.setText("已启用\nBSSID: "+config.getFakeBSSID()+"\nMAC: "+config.getFakeMAC()+"\nSSID: "+config.getFakeSSID());
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

            // 用ScrollView包裹日志内容
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
