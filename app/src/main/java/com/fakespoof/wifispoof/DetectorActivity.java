package com.fakespoof.wifispoof;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.ViewGroup;
import android.view.Gravity;
import android.graphics.Color;
import android.graphics.Typeface;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class DetectorActivity extends Activity {
    private WifiDetector detector;
    private LinearLayout resultContainer;
    private SpoofConfig config;
    private static final int PERMISSION_REQUEST_CODE = 1001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 请求定位权限（Android 6.0+）
        requestLocationPermission();

        // 创建布局
        ScrollView scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(0xFF1A1A2E);
        scrollView.setPadding(32, 32, 32, 32);

        LinearLayout mainLayout = new LinearLayout(this);
        mainLayout.setOrientation(LinearLayout.VERTICAL);

        // 标题
        TextView title = createStyledTextView("WiFi 信息检测", 24, 0xFFE8C547, true);
        title.setPadding(0, 0, 0, 32);
        mainLayout.addView(title);

        // 刷新按钮
        Button btnRefresh = new Button(this);
        btnRefresh.setText("刷新检测");
        btnRefresh.setBackgroundColor(0xFF533483);
        btnRefresh.setTextColor(0xFFFFFFFF);
        btnRefresh.setPadding(16, 16, 16, 16);
        btnRefresh.setOnClickListener(v -> refreshResults());
        mainLayout.addView(btnRefresh);

        // 伪造配置显示
        TextView configTitle = createStyledTextView("\n当前伪造配置:", 16, 0xFFE8C547, true);
        configTitle.setPadding(0, 24, 0, 8);
        mainLayout.addView(configTitle);

        TextView configInfo = createStyledTextView("", 14, 0xFFEAEAEA, false);
        configInfo.setBackgroundColor(0xFF16213E);
        configInfo.setPadding(16, 16, 16, 16);
        mainLayout.addView(configInfo);

        // 分隔线
        TextView divider = new TextView(this);
        divider.setHeight(2);
        divider.setBackgroundColor(0xFF533483);
        LinearLayout.LayoutParams dividerParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 2);
        dividerParams.setMargins(0, 24, 0, 24);
        divider.setLayoutParams(dividerParams);
        mainLayout.addView(divider);

        // 结果容器
        resultContainer = new LinearLayout(this);
        resultContainer.setOrientation(LinearLayout.VERTICAL);
        mainLayout.addView(resultContainer);

        scrollView.addView(mainLayout);
        setContentView(scrollView);

        detector = new WifiDetector(this);
        config = new SpoofConfig(this);

        // 显示配置信息
        String configText = "启用状态: " + (config.isEnabled() ? "是" : "否") + "\n"
            + "伪造BSSID: " + config.getFakeBSSID() + "\n"
            + "伪造MAC: " + config.getFakeMAC() + "\n"
            + "伪造SSID: " + config.getFakeSSID();
        configInfo.setText(configText);

        // 初始加载
        refreshResults();
    }

    private void requestLocationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(
                    new String[]{
                        Manifest.permission.ACCESS_FINE_LOCATION,
                        Manifest.permission.ACCESS_COARSE_LOCATION
                    },
                    PERMISSION_REQUEST_CODE
                );
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == PERMISSION_REQUEST_CODE) {
            boolean granted = false;
            for (int result : grantResults) {
                if (result == PackageManager.PERMISSION_GRANTED) {
                    granted = true;
                    break;
                }
            }
            if (granted) {
                // 权限已获取，刷新结果
                refreshResults();
            }
        }
    }

    private void refreshResults() {
        resultContainer.removeAllViews();

        // 时间戳
        String timestamp = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        TextView timeView = createStyledTextView("刷新时间: " + timestamp + " (已触发WiFi扫描)", 12, 0xFF4CAF50, false);
        timeView.setPadding(0, 0, 0, 16);
        resultContainer.addView(timeView);

        // 权限状态提示
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                TextView permWarning = createStyledTextView(
                    "⚠ 定位权限未授予，扫描结果可能为空。请点击\"刷新检测\"并授权。",
                    12, 0xFFFF9800, true);
                permWarning.setPadding(0, 0, 0, 16);
                resultContainer.addView(permWarning);
            }
        }

        // 说明文字
        TextView desc = createStyledTextView(
            "以下展示通过不同方式获取的WiFi信息，可对比验证伪造效果：\n" +
            "• App层API - 应用常用的WifiManager API\n" +
            "• Java层 - NetworkInterface系统级读取\n" +
            "• 系统属性 - 底层系统属性\n" +
            "• 底层网络 - DhcpInfo/NetworkCapabilities\n" +
            "• WiFi扫描 - 扫描结果交叉验证\n" +
            "• 标注 ⚠ 为系统占位值，✓ 为真实值",
            12, 0xFFAAAAAA, false);
        desc.setPadding(0, 0, 0, 24);
        resultContainer.addView(desc);

        // 获取所有检测结果（带强制扫描）
        List<WifiDetector.WifiInfoResult> results = detector.getAllResultsWithScan();

        // 显示检测摘要
        WifiDetector.DetectionSummary summary = detector.getSummary();
        addSummaryCard(summary);

        // 显示详细结果
        for (int i = 0; i < results.size(); i++) {
            WifiDetector.WifiInfoResult result = results.get(i);
            addResultCard(result, i);
        }
    }

    private void addSummaryCard(WifiDetector.DetectionSummary summary) {
        // 摘要卡片
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(0xFF1E3A5F);
        card.setPadding(24, 24, 24, 24);
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 24);
        card.setLayoutParams(cardParams);

        // 标题
        TextView title = createStyledTextView("🔍 检测结论", 16, 0xFFE8C547, true);
        card.addView(title);

        // 总体评估
        String assessment = summary.getOverallAssessment();
        int assessmentColor = summary.hasIssues() ? 0xFFFF9800 : 0xFF4CAF50;
        TextView assessmentView = createStyledTextView(assessment, 14, assessmentColor, true);
        assessmentView.setPadding(0, 12, 0, 8);
        card.addView(assessmentView);

        // 发现的问题列表
        if (!summary.getFindings().isEmpty()) {
            TextView findingsTitle = createStyledTextView("发现的问题:", 12, 0xFFAAAAAA, false);
            findingsTitle.setPadding(0, 8, 0, 4);
            card.addView(findingsTitle);

            for (WifiDetector.DetectionFinding finding : summary.getFindings()) {
                // 问题标题
                String levelIcon = "";
                int levelColor = 0xFFAAAAAA;
                if (finding.level == WifiDetector.FindingLevel.WARNING) {
                    levelIcon = "⚠ ";
                    levelColor = 0xFFFF9800;
                } else if (finding.level == WifiDetector.FindingLevel.SUSPICIOUS) {
                    levelIcon = "❌ ";
                    levelColor = 0xFFF44336;
                } else {
                    levelIcon = "ℹ ";
                    levelColor = 0xFF2196F3;
                }

                TextView findingTitle = createStyledTextView(levelIcon + finding.title, 12, levelColor, true);
                findingTitle.setPadding(16, 8, 0, 2);
                card.addView(findingTitle);

                // 问题详情
                TextView findingDetail = createStyledTextView(finding.detail, 11, 0xFFCCCCCC, false);
                findingDetail.setPadding(32, 0, 0, 2);
                card.addView(findingDetail);

                // 建议
                if (finding.suggestion != null && !finding.suggestion.isEmpty()) {
                    TextView findingSuggestion = createStyledTextView("→ " + finding.suggestion, 11, 0xFF888888, false);
                    findingSuggestion.setPadding(32, 0, 0, 8);
                    card.addView(findingSuggestion);
                }
            }
        }

        resultContainer.addView(card);
    }

    private void addResultCard(WifiDetector.WifiInfoResult result, int index) {
        // 卡片容器
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(0xFF16213E);
        card.setPadding(24, 24, 24, 24);
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 24);
        card.setLayoutParams(cardParams);

        // 来源标题
        int titleColor = result.success ? 0xFF4CAF50 : 0xFFF44336;
        TextView sourceTitle = createStyledTextView(result.source, 16, titleColor, true);
        card.addView(sourceTitle);

        // 状态指示
        String statusText = result.success ? "✓ 获取成功" : "✗ 获取失败: " + result.error;
        TextView status = createStyledTextView(statusText, 12,
            result.success ? 0xFF4CAF50 : 0xFFF44336, false);
        status.setPadding(0, 8, 0, 16);
        card.addView(status);

        if (result.success) {
            // 显示获取到的信息（带备注）
            addInfoRowWithNote(card, "BSSID", result.bssid, result.bssidNote);
            addInfoRowWithNote(card, "SSID", result.ssid, result.ssidNote);
            addInfoRowWithNote(card, "MAC地址", result.macAddress, result.macNote);
            addInfoRow(card, "IP地址", result.ipAddress);
            addInfoRow(card, "IPv6地址", result.ipv6Address);
            addInfoRow(card, "网络ID", result.networkId);
            addInfoRow(card, "信号强度", result.rssi);
            addInfoRow(card, "连接速度", result.linkSpeed);
            addInfoRowWithNote(card, "频率", result.frequency, result.frequencyNote);
            addInfoRow(card, "加密方式", result.capabilities);

            // 接口信息
            addInfoRow(card, "接口名称", result.interfaceName);
            addInfoRow(card, "接口显示名", result.interfaceDisplayName);
            addInfoRow(card, "是否启用", result.isUp);
            addInfoRow(card, "MTU", result.mtu);

            // 系统属性
            addInfoRow(card, "WiFi驱动版本", result.wlanDriverVersion);
            addInfoRow(card, "WiFi接口", result.wlanInterface);
            addInfoRow(card, "WiFi芯片", result.wlanChipsetName);
            addInfoRow(card, "WiFi直连接口", result.wifiDirectInterface);

            // 网络信息
            addInfoRow(card, "网关", result.gateway);
            addInfoRow(card, "子网掩码", result.netmask);
            addInfoRow(card, "DNS1", result.dns1);
            addInfoRow(card, "DNS2", result.dns2);
            addInfoRow(card, "DHCP服务器", result.serverAddress);
            addInfoRow(card, "租约时长", result.leaseDuration);
            addInfoRow(card, "WiFi传输", result.hasWifiTransport);
            addInfoRow(card, "蜂窝传输", result.hasCellularTransport);
            addInfoRow(card, "以太网传输", result.hasEthernetTransport);

            // 扫描信息
            addInfoRow(card, "扫描AP数量", result.scannedAPCount);
            addInfoRow(card, "当前BSSID在扫描列表", result.bssidInScanList);

            // 显示扫描到的BSSID列表
            if (result.scannedBSSIDs != null && !result.scannedBSSIDs.isEmpty()) {
                TextView scanTitle = createStyledTextView("\n扫描到的AP:", 12, 0xFFAAAAAA, false);
                scanTitle.setPadding(0, 8, 0, 4);
                card.addView(scanTitle);

                for (int i = 0; i < Math.min(result.scannedBSSIDs.size(), 8); i++) {
                    String apInfo = result.scannedBSSIDs.get(i) + " - " +
                        (i < result.scannedSSIDs.size() ? result.scannedSSIDs.get(i) : "N/A");
                    TextView apText = createStyledTextView("  " + apInfo, 11, 0xFFCCCCCC, false);
                    card.addView(apText);
                }
                if (result.scannedBSSIDs.size() > 8) {
                    TextView more = createStyledTextView("  ... 还有 " +
                        (result.scannedBSSIDs.size() - 8) + " 个AP", 11, 0xFF888888, false);
                    card.addView(more);
                }
            }
        }

        resultContainer.addView(card);
    }

    private void addInfoRow(LinearLayout parent, String label, String value) {
        addInfoRowWithNote(parent, label, value, null);
    }

    private void addInfoRowWithNote(LinearLayout parent, String label, String value, String note) {
        if (value == null || value.equals("N/A") || value.isEmpty()) return;

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, 4, 0, 4);

        TextView labelView = createStyledTextView(label + ": ", 13, 0xFF888888, false);
        labelView.setWidth(280);
        row.addView(labelView);

        // 检查是否与伪造值匹配
        boolean isSpoofed = checkIfSpoofed(label, value);
        int valueColor = isSpoofed ? 0xFF4CAF50 : 0xFFFFFFFF;

        // 如果有备注，显示在值后面
        String displayValue = value;
        if (note != null && !note.isEmpty()) {
            displayValue = value + "  " + note;
            // 占位值用橙色标记
            if (note.contains("⚠")) {
                valueColor = 0xFFFF9800;
            } else if (note.contains("✓")) {
                valueColor = 0xFF4CAF50;
            }
        }

        TextView valueView = createStyledTextView(displayValue, 13, valueColor, false);
        row.addView(valueView);

        parent.addView(row);
    }

    private boolean checkIfSpoofed(String label, String value) {
        if (!config.isEnabled()) return false;

        if (label.equals("BSSID") && value.equals(config.getFakeBSSID())) return true;
        if (label.equals("MAC地址") && value.equals(config.getFakeMAC())) return true;
        if (label.equals("SSID") && value.equals(config.getFakeSSID())) return true;
        if (label.equals("SSID") && value.equals(config.getFakeSSID().replace("\"", ""))) return true;

        return false;
    }

    private TextView createStyledTextView(String text, int textSize, int color, boolean bold) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(textSize);
        tv.setTextColor(color);
        if (bold) {
            tv.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return tv;
    }
}
