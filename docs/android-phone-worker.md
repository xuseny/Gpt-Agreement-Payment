# Android 手机 Worker 全自动 OTP

这份文档用于把插在本机 Windows 上的安卓手机，接入服务器 WebUI 的 GoPay OTP 自动流程。

目标链路：

```text
服务器 WebUI / pipeline
  -> 等待 GoPay WhatsApp OTP
本机 android_phone_worker.py
  -> Appium 读取手机通知
  -> 推送 OTP 到服务器 /api/whatsapp/sidecar/state
gopay.py
  -> 自动从 WebUI SQLite latest-otp 继续执行
```

## 1. 服务器确认最新代码

服务器上应已经是最新提交：

```bash
cd /opt/Gpt-Agreement-Payment
git log -1 --oneline
```

应看到类似：

```text
8aa8f51 完善安卓真机对接支持
```

服务状态确认：

```bash
systemctl status gpt-agreement-webui.service --no-pager -l
curl -i http://127.0.0.1:8765/api/healthz
```

## 2. 服务器取 relay token

本机 worker 推送 OTP 时需要 WebUI 的 relay token。服务器执行：

```bash
cd /opt/Gpt-Agreement-Payment
.venv/bin/python - <<'PY'
from webui.backend import wa_relay
print(wa_relay.relay_token())
PY
```

记下输出的 token。

如果 systemd 里配置了自定义 `WEBUI_DATA_DIR`，需要带上同一个环境变量执行上面的命令。

## 3. 本机配置 phone_worker

本机编辑：

```text
CTF-pay/config.android-gopay.example.json
```

把 `phone_worker` 改成你的服务器地址和 token：

```json
"phone_worker": {
  "server_base_url": "https://你的服务器域名或IP",
  "relay_token": "服务器上取到的token",
  "push_path": "/api/whatsapp/sidecar/state",
  "notification_source": "adb",
  "poll_interval_s": 2,
  "ignore_existing_on_start": true
}
```

如果你的 WebUI 是通过 `/webui/` 反代访问，就写：

```json
"server_base_url": "https://你的域名/webui"
```

## 4. 本机确认 ADB

保持手机 USB 连接、解锁、已开启 USB 调试。

PowerShell：

```powershell
adb devices
```

默认 `notification_source=adb`，OTP worker 通过 `adb shell dumpsys notification --noredact`
读取通知，不依赖 Appium Settings。Appium 只在后续录制 / 执行 GoPay 解绑 UI 时需要。

如果你要强制使用 Appium 通知接口，再把 `notification_source` 改成 `appium`，并启动：

```powershell
appium --base-path /
```

Appium 模式下还需要确认通知权限：

```powershell
adb -s <adb_serial> shell cmd notification allow_listener io.appium.settings/.NLService
adb -s <adb_serial> shell settings get secure enabled_notification_listeners
```

输出里应包含：

```text
io.appium.settings/io.appium.settings.NLService
```

## 5. 测试 worker

先 dry-run，不推送服务器：

```powershell
python CTF-pay/android_phone_worker.py --config CTF-pay/config.android-gopay.example.json --once --dry-run --push-existing
```

如果当前手机通知里没有 OTP，返回没有找到是正常的。

确认服务器 token 和地址无误后，测试推送一次：

```powershell
python CTF-pay/android_phone_worker.py --config CTF-pay/config.android-gopay.example.json --once --push-existing
```

然后服务器检查：

```bash
curl -i "http://127.0.0.1:8765/api/whatsapp/latest-otp?token=<relay_token>"
```

如果有新 OTP，应返回 JSON；没有新 OTP 返回 `204`。

## 6. 常驻运行

本机 PowerShell：

```powershell
python CTF-pay/android_phone_worker.py --config CTF-pay/config.android-gopay.example.json
```

默认 `ignore_existing_on_start=true`，启动时看到的旧通知不会推送，避免把过期 OTP 当成新 OTP。正式跑任务前先启动 worker。

## 7. 代理池随机选择

安卓全局代理支持随机池：

```json
"android_automation": {
  "proxy": {
    "enabled": true,
    "pool": [
      "127.0.0.1:18898",
      {"host": "127.0.0.1", "port": 18899},
      "http://user:pass@127.0.0.1:18900"
    ],
    "clear_on_exit": false
  }
}
```

每次 worker 或 unlink 流程设置代理时，会从 `pool` 里随机取一个。Android 全局代理只接受 `host:port`，带账号密码的代理要先用 gost/Clash 转成本地无鉴权端口。

## 8. 还差 GoPay 解绑全自动

OTP 链路可以先全自动跑起来。GoPay 解绑还需要录真实页面：

```powershell
python CTF-pay/android_gopay_automation.py --config CTF-pay/config.android-gopay.example.json inspect --out output/gopay-unlink-inspect
```

把生成的：

```text
output/gopay-unlink-inspect/page.xml
output/gopay-unlink-inspect/screen.png
```

交给我后，可以把 `android_automation.gopay_unlink.steps` 写成真正自动点击流程。
