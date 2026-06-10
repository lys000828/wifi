# WifiSpoof 配置指南

## 功能说明
WifiSpoof 是一个 Xposed 模块，用于伪造所有 App 获取到的 WiFi BSSID、MAC 地址和 SSID 信息。

## 安装步骤

### 1. 安装 Xposed 框架
确保你的设备已安装以下任一框架：
- **LSPosed** (推荐，需要 Magisk/KernelSU)
- **EdXposed**
- **Dreamland**

### 2. 安装 WifiSpoof 模块
1. 编译或下载 WifiSpoof APK
2. 安装到设备上
3. **不要打开 App**

### 3. 在 Xposed 管理器中启用模块

#### LSPosed 用户：
1. 打开 LSPosed 管理器
2. 进入「模块」页面
3. 找到「WifiSpoof」，点击启用
4. **关键步骤**：点击「作用域」
   - 选择「**所有应用**」（推荐）
   - 或者手动选择你需要 hook 的 App

#### EdXposed 用户：
1. 打开 EdXposed Manager
2. 进入「模块」页面
3. 启用 WifiSpoof
4. 在作用域中选择「所有应用」

### 4. 重启设备
启用模块后必须**完全重启设备**（不是仅重启 App）

### 5. 配置伪造信息
1. 打开 WifiSpoof App
2. 输入你想要的伪造值：
   - **BSSID**：WiFi 接入点 MAC 地址（格式：AA:BB:CC:DD:EE:FF）
   - **MAC**：设备 WiFi MAC 地址（格式：AA:BB:CC:DD:EE:FF）
   - **SSID**：WiFi 名称
3. 确保「启用」开关已打开
4. 点击「保存」

### 6. 验证效果
1. 强制停止你要测试的 App
2. 重新打开该 App
3. 在 WifiSpoof App 中点击「查看日志」检查 hook 是否成功

## 常见问题

### Q: 为什么修改后没有生效？
A: 请检查以下几点：
1. Xposed 模块是否已启用
2. 作用域是否包含目标 App（推荐选择「所有应用」）
3. 是否已重启设备
4. 目标 App 是否已强制停止并重新打开
5. 查看日志确认 hook 是否成功

### Q: 如何查看 hook 日志？
A: 在 WifiSpoof App 中点击「查看日志」按钮，日志文件位于 `/sdcard/wifispoof_hook.log`

### Q: 哪些 App 无法被 hook？
A: 以下情况可能无法生效：
1. 使用 NDK 直接读取 WiFi 信息的 App
2. 使用系统 API 但不通过 WifiManager 的 App
3. 某些银行类 App 可能有反 hook 机制

### Q: Android 版本限制？
A: 
- Android 10+ 对 WiFi 信息有系统级限制，返回占位值
- WifiSpoof 会 hook 多个层面来绕过这些限制
- 部分功能可能需要 Root 权限

## 调试信息

### 日志文件位置
- Hook 日志：`/sdcard/wifispoof_hook.log`
- Xposed 日志：在 LSPosed/EdXposed 管理器中查看

### 成功标志
在日志中看到以下内容表示 hook 成功：
```
✓ android.net.wifi.WifiManager.getConnectionInfo
✓ android.net.wifi.WifiInfo.getBSSID
✓ android.net.wifi.WifiInfo.getMacAddress
```

### 失败标志
看到 `✗` 开头的内容表示 hook 失败，需要检查具体错误信息。
