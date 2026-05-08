# Android GoPay 多实例 lane 扩容手册

这份文档用于一套一套增加 WebUI 项目实例、本地模拟器和 Android phone worker。目标是让每个 lane 都有独立的端口、数据库、WhatsApp / GoPay 账号、ADB 设备和 worker 状态，避免 OTP、日志、解绑流程串线。

## 绑定模型

每个 lane 固定绑定这几项：

| 项 | lane-01 | lane-02 示例 | 下一套规则 |
|---|---|---|---|
| 服务器项目目录 | `/opt/Gpt-Agreement-Payment-lane-01` | `/opt/Gpt-Agreement-Payment-lane-02` | 目录递增 |
| WebUI 端口 | `8765` | `8766` | 端口递增 |
| `WEBUI_DATA_DIR` | `.../lane-01/output` | `.../lane-02/output` | 每套独立 |
| `WEBUI_INTERNAL_BASE_URL` | `http://127.0.0.1:8765` | `http://127.0.0.1:8766` | 必须对应本套端口 |
| 模拟器 ADB | `127.0.0.1:16416` | `127.0.0.1:16448` | 使用实际 `adb devices` 输出 |
| Appium 端口 | `4723` | `4724` | 端口递增 |
| UiAutomator2 `systemPort` | `8201` | `8202` | 端口递增 |
| 本地 worker 配置 | `config.android-gopay.lane-01.local.json` | `config.android-gopay.lane-02.local.json` | 文件递增 |

原则很简单：`server_base_url + relay_token` 绑定到服务器实例，`adb_serial + appium_server_url + systemPort` 绑定到本地模拟器。

## 本次先加 lane-02

仓库里已经准备了这些入口文件：

| lane | 服务器启动脚本 | 本地 worker 启动脚本 | 本地 worker 配置 |
|---|---|---|---|
| lane-01 | `scripts/start_webui_lane_01.sh` | `start_android_phone_worker_lane_01.bat` | `CTF-pay/config.android-gopay.lane-01.local.json` |
| lane-02 | `scripts/start_webui_lane_02.sh` | `start_android_phone_worker_lane_02.bat` | `CTF-pay/config.android-gopay.lane-02.local.json` |

本地配置文件属于真实运行配置，已在 `.gitignore` 里忽略。你只需要把里面的 `server_base_url`、`relay_token`、GoPay 手机号/PIN 按 lane 填好。

## lane-01 实操记录

这次 lane-01 已经按多实例方式跑通，实际经验如下，后面加新 lane 时照这个检查。

### 1. 服务器目录和数据库

lane-01 使用原单套运行数据，目录是：

```text
/opt/Gpt-Agreement-Payment-lane-01
/opt/Gpt-Agreement-Payment-lane-01/output/webui.db
```

lane-02 是空 `output` 起步，会首次启动时生成自己的 `webui.db`。只要每个 lane 的 `WEBUI_DATA_DIR` 指向自己的 `output`，数据库、relay token、WhatsApp session、运行状态就不会互相干扰。

检查：

```bash
ls -lh /opt/Gpt-Agreement-Payment-lane-01/output/webui.db
ls -lh /opt/Gpt-Agreement-Payment-lane-02/output/webui.db
```

### 2. WebUI 必须监听公网或反代入口

第一次 lane-01 服务只监听了：

```text
127.0.0.1:8765
```

本地 worker 访问 `http://服务器IP:8765` 时出现：

```text
curl: (52) Empty reply from server
```

修复方式是给 systemd 增加 `HOST=0.0.0.0`：

```bash
mkdir -p /etc/systemd/system/gpt-agreement-webui-lane-01.service.d

cat >/etc/systemd/system/gpt-agreement-webui-lane-01.service.d/override.conf <<'EOF'
[Service]
Environment=HOST=0.0.0.0
EOF

systemctl daemon-reload
systemctl restart gpt-agreement-webui-lane-01.service
```

检查：

```bash
ss -lntp | grep ':8765'
curl -i http://127.0.0.1:8765/api/healthz
```

应看到 `0.0.0.0:8765`，本地 Windows 也应能访问：

```powershell
curl.exe -i http://服务器IP:8765/api/healthz
```

如果不想暴露端口，也可以继续用 `/webui` 反代入口；那本地配置里的 `server_base_url` 要写反代后的完整 base，例如：

```json
"server_base_url": "http://服务器IP/webui"
```

### 3. relay token 必须从对应 lane 获取

lane-01：

```bash
cd /opt/Gpt-Agreement-Payment-lane-01
WEBUI_DATA_DIR=/opt/Gpt-Agreement-Payment-lane-01/output \
.venv/bin/python - <<'PY'
from webui.backend import wa_relay
print(wa_relay.relay_token())
PY
```

lane-02：

```bash
cd /opt/Gpt-Agreement-Payment-lane-02
WEBUI_DATA_DIR=/opt/Gpt-Agreement-Payment-lane-02/output \
.venv/bin/python - <<'PY'
from webui.backend import wa_relay
print(wa_relay.relay_token())
PY
```

不要把 lane-01 的 token 填到 lane-02。token 和 `WEBUI_DATA_DIR/output/webui.db` 是一一对应的。

### 4. lane venv 里要装完整运行依赖

WebUI 能启动不代表注册/支付流程依赖都齐。lane-01 注册时报过：

```text
ModuleNotFoundError: No module named 'camoufox'
```

每个服务器 lane 都要在自己的 `.venv` 里装核心依赖：

```bash
cd /opt/Gpt-Agreement-Payment-lane-01
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install requests curl_cffi playwright camoufox browserforge mitmproxy pybase64
.venv/bin/playwright install firefox
.venv/bin/camoufox fetch

.venv/bin/python -c "import camoufox, playwright, curl_cffi; print('core ok')"
```

lane-02 同理，把路径换成 `/opt/Gpt-Agreement-Payment-lane-02`。

### 5. pipeline 子进程必须用当前 venv Python

lane-01 还踩过一个点：`pipeline.py` 的注册子进程如果默认调用系统 `python3`，即使 `.venv` 里装了 `camoufox`，注册仍然会报缺模块。

现在代码应保证：

```python
def register(..., python=None, ...):
    python = python or sys.executable

def pay(..., python=None, ...):
    python = python or sys.executable
```

如果服务器 lane 是旧代码，先同步或 patch `pipeline.py`，再重启服务：

```bash
systemctl restart gpt-agreement-webui-lane-01.service
```

验证注册日志里不应再从系统 `python3` 报 `No module named 'camoufox'`。

### 6. 本地 lane-01 worker 配置参考稳定版

lane-01 的本地配置最终以稳定版 `CTF-pay/config.android-gopay.local.json` 为基准，只改 lane 绑定项。

稳定行为保持：

```json
"push_delay_after_notification_s": 20,
"otp_focus": {
  "enabled": true,
  "focus_on_run_log": true
}
```

lane-01 当前额外启用了更稳的 OTP 读取窗口：

```json
"otp_focus": {
  "read_delay_after_run_log_trigger_s": 10,
  "push_immediately_after_run_log_trigger": true
}
```

含义：

```text
服务器日志出现 GoPay 等待 WhatsApp OTP 后，worker 先等 10 秒；
10 秒后再读取 Android 通知；
一旦读到验证码就直接推送，不再叠加 push_delay_after_notification_s 的 20 秒等待。
```

lane-01 独立绑定项：

```json
"phone_worker": {
  "server_base_url": "http://服务器IP:8765",
  "state_file": "output/lane-01/android-phone-worker-state.json",
  "gopay_unlink": {
    "out_dir": "output/lane-01/android-gopay-unlink"
  }
},
"android_automation": {
  "adb_serial": "127.0.0.1:16416",
  "adb_connect_serials": ["127.0.0.1:16416"],
  "appium_server_url": "http://127.0.0.1:4723",
  "capabilities": {
    "systemPort": 8201,
    "mjpegServerPort": 9201,
    "chromedriverPort": 9511
  }
}
```

本地启动：

```powershell
.\start_android_phone_worker_lane_01.bat
```

读取测试：

```powershell
python CTF-pay/android_phone_worker.py --config CTF-pay/config.android-gopay.lane-01.local.json --once --dry-run --push-existing
```

没有 OTP 通知时返回未找到是正常的；有 GoPay/WhatsApp 通知时应打印待推送 payload。

### 7. worker 旧 OTP 挡住新 OTP 的修复

lane-01 实测出现过 worker 启动后只打印两行：

```text
[android-phone-worker] skip otp 399008 (initial_existing_notification)
[android-phone-worker] skip otp 399008 (duplicate_fingerprint)
```

之后新验证码来了也不推送、服务器等待 OTP 日志也看起来没反应。根因是旧版本 worker 每轮只选一个“最佳 OTP 候选”；如果通知栏里旧 OTP 排名更高，它会被重复跳过，后面的新 OTP 没机会被处理。

现在 `CTF-pay/android_phone_worker.py` 已改成：

```text
1. 每轮提取所有 OTP 候选；
2. 旧通知 / 重复 fingerprint 被跳过后继续看下一个候选；
3. worker 启动时如果服务器已经处于 otp_pending，也会响应当前等待 OTP 的日志；
4. 服务器已在等待 OTP 时，首次扫描到的当前通知不会再被 initial_existing_notification 误跳过；
5. 可配置为服务器 OTP 日志触发后等待 N 秒再读通知，读到后立即推送。
```

本地更新代码后，重启对应 worker 即可生效：

```powershell
Ctrl+C
.\start_android_phone_worker_lane_01.bat
```

如果仍然只看到同一个旧 OTP，可以先清掉本 lane 的 worker 状态文件后再启动：

```powershell
Remove-Item output\lane-01\android-phone-worker-state.json -ErrorAction SilentlyContinue
.\start_android_phone_worker_lane_01.bat
```

### 1. 服务器复制第二套项目

下面以第一套已经在 `/opt/Gpt-Agreement-Payment-lane-01`，第二套放到 `/opt/Gpt-Agreement-Payment-lane-02` 为例。

```bash
sudo rsync -a \
  --exclude output \
  --exclude __pycache__ \
  /opt/Gpt-Agreement-Payment-lane-01/ \
  /opt/Gpt-Agreement-Payment-lane-02/

cd /opt/Gpt-Agreement-Payment-lane-02
mkdir -p output
```

如果你的第一套目录就是 `/opt/Gpt-Agreement-Payment`，把上面的源目录换成它即可。依赖环境可以复用原来的安装方式；如果每套项目有自己的 `.venv`，就在 lane-02 目录里按原项目安装流程再建一次。

### 2. 启动 lane-02 WebUI

临时前台验证：

```bash
cd /opt/Gpt-Agreement-Payment-lane-02
bash scripts/start_webui_lane_02.sh
```

systemd 推荐服务：

```ini
# /etc/systemd/system/gpt-agreement-webui-lane-02.service
[Unit]
Description=Gpt Agreement WebUI lane-02
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/Gpt-Agreement-Payment-lane-02
Environment=PYTHONUNBUFFERED=1
Environment=WEBUI_DATA_DIR=/opt/Gpt-Agreement-Payment-lane-02/output
Environment=WEBUI_INTERNAL_BASE_URL=http://127.0.0.1:8766
ExecStart=/bin/bash /opt/Gpt-Agreement-Payment-lane-02/scripts/start_webui_lane_02.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gpt-agreement-webui-lane-02.service
curl -i http://127.0.0.1:8766/api/healthz
```

`WEBUI_INTERNAL_BASE_URL` 很关键。lane-02 如果不设置它，GoPay 进程可能仍然去轮询默认的 `8765` OTP endpoint。

### 3. 取 lane-02 的 relay token

```bash
cd /opt/Gpt-Agreement-Payment-lane-02
WEBUI_DATA_DIR=/opt/Gpt-Agreement-Payment-lane-02/output \
.venv/bin/python - <<'PY'
from webui.backend import wa_relay
print(wa_relay.relay_token())
PY
```

把输出记为：

```text
LANE_02_RELAY_TOKEN=这里替换成实际输出
```

每个 lane 的 token 必须来自对应端口/对应 `WEBUI_DATA_DIR` 的项目实例。

### 4. 本地确认第二个模拟器

在本地 Windows PowerShell：

```powershell
adb devices
```

如果是 MuMu 多开，先连接候选端口，再看实际设备号：

```powershell
adb connect 127.0.0.1:16416
adb connect 127.0.0.1:16448
adb devices
```

示例映射：

```text
127.0.0.1:16416    device    # lane-01
127.0.0.1:16448    device    # lane-02
```

后续 lane-02 必须一直写死 `127.0.0.1:16448`，不要用 `auto`。

### 5. 启动 lane-02 Appium

单独开一个 PowerShell 窗口：

```powershell
$adb = (Get-Command adb).Source
$sdkRoot = Split-Path (Split-Path $adb -Parent) -Parent
$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot
appium --base-path / --port 4724
```

如果你想把 Appium 放后台，确保日志单独写到 lane-02 文件，方便排障。lane-01 用 `4723`，lane-02 用 `4724`，后续继续递增。

### 6. 生成 lane-02 本地 worker 配置

在项目根目录执行：

```powershell
.\scripts\new_android_gopay_lane.ps1 `
  -Lane 02 `
  -ServerBaseUrl "http://你的服务器IP:8766" `
  -RelayToken "LANE_02_RELAY_TOKEN" `
  -AdbSerial "127.0.0.1:16448" `
  -AppiumPort 4724 `
  -SystemPort 8202 `
  -MjpegServerPort 9202 `
  -ChromedriverPort 9522
```

脚本会生成：

```text
CTF-pay/config.android-gopay.lane-02.local.json
```

然后检查并填好这几个账号字段：

```json
"gopay": {
  "country_code": "62",
  "phone_number": "lane-02 的 GoPay 手机号",
  "pin": "lane-02 的 GoPay PIN"
}
```

lane-02 模拟器里需要登录 lane-02 对应的 WhatsApp 和 GoPay 账号。

### 7. 测试 lane-02 worker

本地 dry-run，不推送服务器：

```powershell
python CTF-pay/android_phone_worker.py --config CTF-pay/config.android-gopay.lane-02.local.json --once --dry-run --push-existing
```

真实推送一次：

```powershell
python CTF-pay/android_phone_worker.py --config CTF-pay/config.android-gopay.lane-02.local.json --once --push-existing
```

服务器验证：

```bash
curl -i "http://127.0.0.1:8766/api/whatsapp/latest-otp?token=LANE_02_RELAY_TOKEN"
```

没有新 OTP 返回 `204` 是正常的；有新 OTP 时会返回 JSON。

### 8. 常驻 lane-02 worker

本地单独开一个 PowerShell：

```powershell
python CTF-pay/android_phone_worker.py --config CTF-pay/config.android-gopay.lane-02.local.json
```

这时绑定关系已经固定：

```text
lane-02 WebUI :8766
  <- token: LANE_02_RELAY_TOKEN
  <- worker: config.android-gopay.lane-02.local.json
  <- emulator: 127.0.0.1:16448
  <- appium: 127.0.0.1:4724 / systemPort 8202
```

### 9. 在 lane-02 WebUI 开跑

浏览器打开 lane-02 的 WebUI 地址，例如：

```text
http://你的服务器IP:8766
```

使用 GoPay 时，lane-02 内建议 `workers=1`。GoPay OTP 是“当前最新 OTP”模型，同一 lane 内并发多个支付请求容易互相抢验证码。要扩容就加 lane，不要在单 lane 里加支付并发。

## 下次加 lane-03

只需要按同样规则递增：

| 项 | lane-03 示例 |
|---|---|
| 服务器目录 | `/opt/Gpt-Agreement-Payment-lane-03` |
| WebUI 端口 | `8767` |
| `WEBUI_DATA_DIR` | `/opt/Gpt-Agreement-Payment-lane-03/output` |
| `WEBUI_INTERNAL_BASE_URL` | `http://127.0.0.1:8767` |
| Appium 端口 | `4725` |
| `systemPort` | `8203` |
| 本地配置 | `CTF-pay/config.android-gopay.lane-03.local.json` |

生成本地配置：

```powershell
.\scripts\new_android_gopay_lane.ps1 `
  -Lane 03 `
  -ServerBaseUrl "http://你的服务器IP:8767" `
  -RelayToken "LANE_03_RELAY_TOKEN" `
  -AdbSerial "第三个模拟器的 adb_serial" `
  -AppiumPort 4725 `
  -SystemPort 8203 `
  -MjpegServerPort 9203 `
  -ChromedriverPort 9523
```

## 排障速查

| 现象 | 优先检查 |
|---|---|
| lane-02 收到 lane-01 的 OTP | `server_base_url`、`relay_token` 是否填成 lane-02 |
| worker 报多个设备 | `android_automation.adb_serial` 不要用 `auto` |
| Appium 会话冲突 | Appium 端口和 `capabilities.systemPort` 是否唯一 |
| 重启后旧 OTP 被跳过/误判 | 每个 lane 的 `phone_worker.state_file` 是否唯一 |
| GoPay 解绑产物混在一起 | `phone_worker.gopay_unlink.out_dir` 是否唯一 |
| GoPay 进程轮询错端口 | 服务器 systemd 是否设置了本 lane 的 `WEBUI_INTERNAL_BASE_URL` |
