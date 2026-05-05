# Android 真机对接手册

这份文档用于下次更换手机时，重新把手机接入本项目的 Android/Appium 自动化链路。

目标链路：

```text
Windows 本机
  -> USB / ADB
  -> Android 真机
  -> Appium UiAutomator2
  -> CTF-pay/android_gopay_automation.py
```

真机用于：

- 导出当前手机页面树和截图，辅助录制 GoPay 解绑步骤。
- 从 Android 通知读取 WhatsApp / GoPay OTP。
- 执行配置化的 GoPay App UI 操作。

## 1. 手机准备

在新手机上操作：

1. 打开开发者模式。
   - 设置 -> 关于手机 -> 连续点击“版本号”。
2. 打开 USB 调试。
   - 设置 -> 开发者选项 -> USB 调试。
3. 用 USB 连接电脑。
4. 手机弹出“允许 USB 调试”时，勾选“始终允许”，然后点允许。
5. 保持手机亮屏、解锁，首次对接时不要锁屏。

## 2. 电脑确认 ADB

在项目根目录运行：

```powershell
adb devices
```

正常输出类似：

```text
List of devices attached
3B65AA01QGE00000    device
```

记下 `device` 前面的字符串，这就是新手机的 `adb_serial`。

如果显示 `unauthorized`：

```powershell
adb kill-server
adb start-server
adb devices
```

然后重新在手机上点允许 USB 调试。

如果显示多个设备，后续命令都必须带 `-s <adb_serial>`。

## 3. 修改本地配置

编辑：

```text
CTF-pay/config.android-gopay.example.json
```

把：

```json
"adb_serial": "旧设备号",
"device_name": "旧设备名"
```

改成：

```json
"adb_serial": "新手机 adb_serial",
"device_name": "Android Phone"
```

示例：

```json
"adb_serial": "3B65AA01QGE00000",
"device_name": "Android Phone"
```

如果你想保留模板不动，可以复制一份本机配置：

```powershell
Copy-Item CTF-pay/config.android-gopay.example.json CTF-pay/config.android-gopay.local.json
```

然后后续命令都改用：

```powershell
--config CTF-pay/config.android-gopay.local.json
```

## 4. 安装一次性依赖

如果电脑已经装过，可以跳过。

```powershell
npm install -g appium
appium driver install uiautomator2
python -m pip install -r CTF-pay/requirements.android.txt
```

确认：

```powershell
appium -v
python -c "import appium; print('appium python ok')"
```

## 5. 启动 Appium

Appium 需要能找到 Android SDK 路径。即使只装了 platform-tools，也可以先按下面方式给当前 PowerShell 会话设置环境变量：

```powershell
$adb = (Get-Command adb).Source
$sdkRoot = Split-Path (Split-Path $adb -Parent) -Parent
$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot
appium --base-path /
```

保持这个 PowerShell 窗口运行。

如果 Appium 报：

```text
Neither ANDROID_HOME nor ANDROID_SDK_ROOT environment variable was exported
```

说明上面的环境变量没有在启动 Appium 的同一个窗口里生效，重新设置后再启动。

## 6. Appium Settings 打不开怎么办

`Appium Settings` 是 Appium 自动安装的辅助 App。它不一定像普通 App 一样能从桌面打开，这不是失败。

用 ADB 检查它是否安装：

```powershell
adb -s <adb_serial> shell pm list packages | findstr appium
```

如果看到：

```text
package:io.appium.settings
```

说明已安装。

直接用 ADB 拉起：

```powershell
adb -s <adb_serial> shell am start -W -n io.appium.settings/.Settings
```

如果命令返回 `Status: ok`，就算手机界面没有明显展示，也可以继续。

给它通知访问权限：

```powershell
adb -s <adb_serial> shell cmd notification allow_listener io.appium.settings/.NLService
adb -s <adb_serial> shell settings get secure enabled_notification_listeners
```

正常输出里应包含：

```text
io.appium.settings/io.appium.settings.NLService
```

如果 ADB 授权失败，就在手机里手动搜索：

```text
通知使用权 / Notification access
```

然后启用 `Appium Settings`。

## 7. 验证页面采集

先让手机保持解锁，然后运行：

```powershell
python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json inspect --out output/android-phone-inspect
```

成功时会输出：

```json
{"ok": true, "out_dir": "output\\android-phone-inspect"}
```

并生成：

```text
output/android-phone-inspect/page.xml
output/android-phone-inspect/screen.png
```

这一步成功，说明 ADB + Appium + UiAutomator2 已经通了。

## 8. 验证通知 OTP 读取

短测命令：

```powershell
python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json otp --timeout 10
```

如果当前没有 GoPay / WhatsApp OTP 通知，返回码为 `1` 是正常的。

如果有真实 OTP 通知，脚本应只输出验证码，例如：

```text
123456
```

OnePlus / OPlus 系统偶尔会让 Appium 的 `mobile: getNotifications` 广播短暂失败。脚本会自动重试；如果一直失败，先确认第 6 节的通知访问权限。

可用 ADB 辅助检查当前通知内容：

```powershell
adb -s <adb_serial> shell dumpsys notification --noredact | findstr /i "whatsapp gopay otp kode verification"
```

如果这里能看到通知正文，但脚本读不到，优先检查 Appium Settings 的通知使用权和后台限制。

## 9. 常见问题

### `adb devices` 没有设备

- 换 USB 数据线。
- 手机 USB 模式选择“文件传输”。
- 重新开启 USB 调试。
- 执行：

```powershell
adb kill-server
adb start-server
adb devices
```

### `adb devices` 显示 `unauthorized`

手机上没有点允许 USB 调试。拔插 USB 后重新确认弹窗。

### `inspect` 报 Appium Settings not running

执行：

```powershell
adb -s <adb_serial> shell am start -W -n io.appium.settings/.Settings
```

然后重新跑 `inspect`。

### `getNotifications` 报 retrieve notifications 失败

执行：

```powershell
adb -s <adb_serial> shell cmd notification allow_listener io.appium.settings/.NLService
adb -s <adb_serial> shell settings get secure enabled_notification_listeners
```

确认输出里有 `io.appium.settings/io.appium.settings.NLService`。

### Appium 报缺 `aapt2.exe`

如果只是警告，且 `inspect` 能成功，可以先忽略。

如果会话创建失败，需要安装完整 Android SDK build-tools，或把 `ANDROID_HOME` / `ANDROID_SDK_ROOT` 指到已有 Android SDK 根目录。

## 10. 换手机最短流程

```powershell
adb devices
# 记下新 adb_serial

# 修改 CTF-pay/config.android-gopay.example.json 的 adb_serial

$adb = (Get-Command adb).Source
$sdkRoot = Split-Path (Split-Path $adb -Parent) -Parent
$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot
appium --base-path /
```

另开一个 PowerShell：

```powershell
adb -s <adb_serial> shell am start -W -n io.appium.settings/.Settings
adb -s <adb_serial> shell cmd notification allow_listener io.appium.settings/.NLService

python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json inspect --out output/android-phone-inspect
python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json otp --timeout 10
```
