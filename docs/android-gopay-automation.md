# Android GoPay 自动化

本方案用于把 GoPay 相关的手机端动作迁移到安卓模拟器上：

- 从 Android 通知里读取 WhatsApp / GoPay OTP，并作为 `gopay.otp.command` 输出给 `gopay.py`。
- 对 GoPay App 做页面树采集，产出 `page.xml` 和截图，用来录制稳定 selector。
- 按 JSON 配置执行 GoPay 解绑流程。默认示例只 dump 页面，不会直接点解绑。
- 可选通过 ADB 给模拟器设置 HTTP 代理。

## 推荐环境

- MuMu Player 12
- Python 3.10+
- Node.js 18+
- Appium 2
- Appium UiAutomator2 driver

安装依赖：

```powershell
npm install -g appium
appium driver install uiautomator2
pip install -r CTF-pay/requirements.android.txt
```

MuMu ADB 常见路径：

```powershell
& "C:\Program Files\Netease\MuMu Player 12\shell\adb.exe" connect 127.0.0.1:16384
& "C:\Program Files\Netease\MuMu Player 12\shell\adb.exe" devices
```

如果你的 `adb.exe` 不在 PATH，把 `CTF-pay/config.android-gopay.example.json`
里的 `android_automation.adb_path` 改成完整路径。

## 启动 Appium

单独开一个 PowerShell：

```powershell
appium --base-path /
```

保持窗口运行。第一次使用 `mobile: getNotifications` 时，需要在模拟器里给
`Appium Settings` 开通知访问权限。

## OTP 命令模式

`CTF-pay/config.android-gopay.example.json` 已经把 GoPay OTP 配成 command：

```json
"otp": {
  "source": "command",
  "command": [
    "python",
    "CTF-pay/android_gopay_automation.py",
    "--config",
    "CTF-pay/config.android-gopay.example.json",
    "otp"
  ]
}
```

单独测试：

```powershell
python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json otp
```

它会轮询 Android 通知，匹配 `com.whatsapp` 以及 GoPay/OTP 关键词，找到验证码后只把验证码打印到 stdout。

## 页面树采集

打开模拟器里的 GoPay/Gojek App，手动导航到你要自动化的位置，然后运行：

```powershell
python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json inspect --out output/android-inspect
```

产物：

- `output/android-inspect/page.xml`
- `output/android-inspect/screen.png`

根据 XML 里的 `text`、`resource-id`、`content-desc` 或 XPath，把步骤写到
`android_automation.gopay_unlink.steps`。

## 解绑步骤配置

支持的动作：

- `dump`: 保存当前 XML/截图。
- `wait`: 等元素出现。
- `tap`: 点击元素。
- `input`: 输入文本。
- `back`: 返回。
- `press_keycode`: Android keycode。
- `sleep`: 等待秒数。
- `assert_text_any`: 断言页面里出现任一文本。

元素定位字段任选一个：

- `id`
- `xpath`
- `accessibility_id`
- `text`
- `text_contains`
- `description_contains`

示例骨架：

```json
"gopay_unlink": {
  "package": "com.gojek.app",
  "steps": [
    {"action": "dump", "name": "start"},
    {"action": "tap", "text_contains": "Profile"},
    {"action": "tap", "text_contains": "Payment"},
    {"action": "tap", "text_contains": "OpenAI"},
    {"action": "tap", "text_contains": "Unlink"},
    {"action": "tap", "text_contains": "Confirm"},
    {"action": "assert_text_any", "values": ["Unlinked", "Removed", "Berhasil"]},
    {"action": "dump", "name": "done"}
  ]
}
```

实际文字以你的模拟器页面树为准，不要直接照抄示例。

运行：

```powershell
python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json unlink --out output/android-gopay-unlink
```

## 模拟器代理

如果要让模拟器走本地代理，先把上游代理转成本地无鉴权入口，例如：

```json
"proxy": {
  "enabled": true,
  "host_port": "127.0.0.1:18898",
  "clear_on_exit": false
}
```

脚本会执行：

```text
adb shell settings put global http_proxy 127.0.0.1:18898
```

Android 全局代理只接受 `host:port`，不适合直接填带用户名密码的代理 URL。带鉴权的代理建议先用 gost/Clash 转成本地端口。
