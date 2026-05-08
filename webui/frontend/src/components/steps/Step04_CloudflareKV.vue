<template>
  <section class="step-fade-in">
    <div class="term-divider" data-tail="──────────">步骤 04: 邮箱 OTP</div>
    <h2 class="step-h">$&nbsp;OTP 接收配置<span class="term-cursor"></span></h2>
    <p class="step-sub">
      这里选择注册 / OAuth 登录阶段的邮箱 OTP 来源。默认还是
      <code>CF Email Worker → KV</code>；如果你已经有 Hotmail 邮箱池，也可以直接切到
      <code>Hotmail 邮箱池</code> 并在下面粘贴池内容。
    </p>

    <div class="form-stack">
      <div class="source-switch">
        <button
          class="source-pill"
          :class="{ active: form.source === 'cf_kv' }"
          @click="setSource('cf_kv')"
        >
          CF Email Worker → KV
        </button>
        <button
          class="source-pill"
          :class="{ active: form.source === 'hotmail_pool' }"
          @click="setSource('hotmail_pool')"
        >
          Hotmail 邮箱池
        </button>
      </div>

      <template v-if="form.source === 'cf_kv'">
        <TermField
          v-model="form.api_token"
          label="API Token · api_token"
          type="password"
          :placeholder="defaultTokenPlaceholder"
        />
        <TermField
          v-model="form.fallback_to"
          label="备份转发 · fallback_to (可选)"
          placeholder="抓到 OTP 后同时转发一份到这个邮箱（迁移期保险）"
        />
      </template>

      <template v-else>
        <TermField
          v-model="form.pool_path"
          label="池文件路径 · pool_path"
          placeholder="./hotmail-pool.local.txt"
        />
        <TermField
          v-model="form.state_path"
          label="顺序状态文件 · state_path"
          placeholder="../output/hotmail-pool-state.json"
        />
        <TermField
          v-model="form.delimiter"
          label="分隔符 · delimiter"
          placeholder="----"
        />
        <div class="tf">
          <span class="tf-tag">邮箱池内容 · pool_text</span>
          <textarea
            v-model="form.pool_text"
            class="tf-textarea"
            placeholder="一行一个：邮箱----收件api"
            rows="8"
          ></textarea>
        </div>
        <div class="kv-inline-grid">
          <TermField
            v-model="form.poll_interval_s"
            label="轮询间隔 · poll_interval_s"
            placeholder="3"
          />
          <TermField
            v-model="form.request_timeout_s"
            label="请求超时 · request_timeout_s"
            placeholder="20"
          />
          <TermField
            v-model="form.issued_after_grace_s"
            label="回看窗口 · issued_after_grace_s"
            placeholder="45"
          />
        </div>
      </template>
    </div>

    <div class="step-actions">
      <TermBtn :loading="deploying" @click="submitCurrentSource">
        {{ form.source === 'cf_kv' ? '一键部署 + 测试' : '保存 Hotmail 池配置' }}
      </TermBtn>
    </div>

    <div v-if="deployResult && form.source === 'cf_kv'" class="result-block result--ok" style="margin-top:14px">
      <div class="result-head"><span class="result-icon">✓</span> 部署成功</div>
      <ul class="result-list">
        <li class="row-ok"><span class="row-name">account</span><span class="row-msg">{{ deployResult.account_name }} ({{ deployResult.account_id }})</span></li>
        <li class="row-ok"><span class="row-name">kv_namespace_id</span><span class="row-msg">{{ deployResult.kv_namespace_id }}</span></li>
        <li class="row-ok"><span class="row-name">worker</span><span class="row-msg">{{ deployResult.worker_name }}</span></li>
        <li
          v-for="z in deployResult.zones_configured"
          :key="z.zone"
          :class="z.ok ? 'row-ok' : 'row-fail'"
        >
          <span class="row-name">zone:{{ z.zone }}</span>
          <span class="row-msg">
            {{ z.ok ? `before=[${z.before}] → worker` : `失败: ${z.error}` }}
          </span>
        </li>
        <li v-if="deployResult.secrets_path" class="row-ok">
          <span class="row-name">SQLite runtime_meta[secrets]</span>
          <span class="row-msg">已落 {{ deployResult.secrets_path }}</span>
        </li>
      </ul>
    </div>

    <div v-if="hotmailResult && form.source === 'hotmail_pool'" class="result-block result--ok" style="margin-top:14px">
      <div class="result-head"><span class="result-icon">✓</span> Hotmail 池配置已保存</div>
      <ul class="result-list">
        <li class="row-ok"><span class="row-name">entries</span><span class="row-msg">{{ hotmailResult.entries }} 条</span></li>
        <li class="row-ok"><span class="row-name">pool_path</span><span class="row-msg">{{ hotmailResult.pool_path }}</span></li>
        <li class="row-ok"><span class="row-name">state_path</span><span class="row-msg">{{ hotmailResult.state_path }}</span></li>
      </ul>
    </div>

    <div v-if="error" class="result-block result--fail" style="margin-top:14px">
      <div class="result-head"><span class="result-icon">✗</span> {{ error }}</div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { ref, computed, watch } from "vue";
import { useWizardStore } from "../../stores/wizard";
import type { PreflightResult } from "../../api/client";
import { api } from "../../api/client";
import TermField from "../term/TermField.vue";
import TermBtn from "../term/TermBtn.vue";

const store = useWizardStore();
const cfAns = (store.answers.cloudflare ?? {}) as any;
const init = (store.answers.cloudflare_kv ?? {}) as any;
const DEFAULT_POOL_PATH = "./hotmail-pool.local.txt";
const DEFAULT_STATE_PATH = "../output/hotmail-pool-state.json";
const DEFAULT_DELIMITER = "----";

const form = ref({
  source: init.source ?? "cf_kv",
  api_token: init.api_token ?? "",
  fallback_to: init.fallback_to ?? "",
  pool_path: init.pool_path ?? DEFAULT_POOL_PATH,
  state_path: init.state_path ?? DEFAULT_STATE_PATH,
  delimiter: init.delimiter ?? DEFAULT_DELIMITER,
  pool_text: init.pool_text ?? "",
  poll_interval_s: String(init.poll_interval_s ?? 3),
  request_timeout_s: String(init.request_timeout_s ?? 20),
  issued_after_grace_s: String(init.issued_after_grace_s ?? 45),
});

const defaultTokenPlaceholder = computed(() =>
  cfAns.cf_token ? "留空 = 用 Step 03 的 cf_token" : "粘贴 token"
);

const deploying = ref(false);
const deployResult = ref<any>(
  init.account_id && (init.source ?? "cf_kv") === "cf_kv"
    ? {
        account_name: init.account_name ?? "",
        account_id: init.account_id,
        kv_namespace_id: init.kv_namespace_id,
        worker_name: init.worker_name ?? "otp-relay",
        zones_configured: init.zones_configured ?? [],
        secrets_path: init.secrets_path ?? "",
      }
    : null
);
const hotmailResult = ref<any>(
  (init.source ?? "") === "hotmail_pool" && init.pool_path
    ? {
        entries: countHotmailEntries(init.pool_text ?? "", init.delimiter ?? DEFAULT_DELIMITER),
        pool_path: init.pool_path,
        state_path: init.state_path ?? DEFAULT_STATE_PATH,
      }
    : null
);
const error = ref<string>("");

function normalizeFormForStore() {
  return {
    ...form.value,
    pool_text: normalizePoolText(form.value.pool_text),
  };
}

function normalizePoolText(value: string) {
  return String(value || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
}

function countHotmailEntries(value: string, delimiter: string) {
  const lines = collectHotmailEntries(value, delimiter);
  return lines.length;
}

function collectHotmailEntries(value: string, delimiter: string) {
  const text = normalizePoolText(value);
  const delim = (delimiter || DEFAULT_DELIMITER).trim() || DEFAULT_DELIMITER;
  const valid: string[] = [];
  text.split("\n").forEach((raw, idx) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    if (!line.includes(delim)) {
      return;
    }
    const [email, api] = line.split(delim, 2).map((item) => item.trim());
    if (!email || !api) {
      return;
    }
    valid.push(line);
  });
  return valid;
}

function validateHotmailPool(value: string, delimiter: string) {
  const text = normalizePoolText(value);
  const delim = (delimiter || DEFAULT_DELIMITER).trim() || DEFAULT_DELIMITER;
  const valid: string[] = [];
  const invalid: number[] = [];
  text.split("\n").forEach((raw, idx) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    if (!line.includes(delim)) {
      invalid.push(idx + 1);
      return;
    }
    const [email, api] = line.split(delim, 2).map((item) => item.trim());
    if (!email || !api) {
      invalid.push(idx + 1);
      return;
    }
    valid.push(line);
  });
  return { valid, invalid, delim };
}

function setSource(source: "cf_kv" | "hotmail_pool") {
  if (form.value.source === source) return;
  form.value.source = source;
  error.value = "";
  deployResult.value = null;
  hotmailResult.value = null;
  if (source === "cf_kv") {
    store.setPreflight("cloudflare_kv", {
      status: "warn",
      message: "已切回 Cloudflare KV；完成部署后才能继续",
      checks: [],
    });
  } else {
    store.setPreflight("cloudflare_kv", {
      status: "warn",
      message: "已切到 Hotmail 池；保存配置后才能继续",
      checks: [],
    });
  }
}

async function deployCfKv() {
  error.value = "";
  deployResult.value = null;
  hotmailResult.value = null;
  const token = (form.value.api_token || cfAns.cf_token || "").trim();
  if (!token) {
    error.value = "缺 API token（要么填这里，要么在 Step 03 填 cf_token）";
    return;
  }
  const zones: string[] = (cfAns.zone_names ?? []) as string[];
  if (!zones.length) {
    error.value = "Step 03 还没填 zone_names，先回 Step 03 配 zones";
    return;
  }

  deploying.value = true;
  try {
    const r = await api.post("/cloudflare_kv/auto-setup", {
      api_token: token,
      zones,
      worker_name: "otp-relay",
      kv_name: "OTP_KV",
      fallback_to: form.value.fallback_to,
    });
    const res = r.data;
    deployResult.value = res;
    // 答案里把回来的字段也存上，下次进 wizard 直接显示
    store.setAnswer("cloudflare_kv", {
      source: "cf_kv",
      api_token: token,
      fallback_to: form.value.fallback_to,
      account_id: res.account_id,
      account_name: res.account_name,
      kv_namespace_id: res.kv_namespace_id,
      worker_name: res.worker_name,
      zones_configured: res.zones_configured,
      secrets_path: res.secrets_path,
    });
    await store.saveToServer();

    // 一键部署成功也给 preflight 写一个 ok，方便 step gate 解锁
    const allOk = (res.zones_configured ?? []).every((z: any) => z.ok);
    const result: PreflightResult = allOk
      ? { status: "ok", message: `部署完成，${res.zones_configured.length} 个 zone 已切到 worker`, checks: [] }
      : { status: "warn", message: "部署部分成功，看上面 zone 列表", checks: [] };
    store.setPreflight("cloudflare_kv", result);
  } catch (e: any) {
    error.value = e?.response?.data?.detail || String(e);
  } finally {
    deploying.value = false;
  }
}

async function saveHotmailPool() {
  error.value = "";
  deployResult.value = null;
  hotmailResult.value = null;
  const checked = validateHotmailPool(form.value.pool_text, form.value.delimiter);
  if (!checked.valid.length) {
    error.value = "邮箱池不能为空，至少要有一行 `邮箱----收件api`";
    store.setPreflight("cloudflare_kv", {
      status: "fail",
      message: "Hotmail 池为空",
      checks: [],
    });
    return;
  }
  if (checked.invalid.length) {
    error.value = `以下行格式不正确：${checked.invalid.join(", ")}，需要 \`邮箱${checked.delim}收件api\``;
    store.setPreflight("cloudflare_kv", {
      status: "fail",
      message: "Hotmail 池格式错误",
      checks: [],
    });
    return;
  }

  const answer = {
    ...normalizeFormForStore(),
    source: "hotmail_pool",
  };
  store.setAnswer("cloudflare_kv", answer);
  await store.saveToServer();
  hotmailResult.value = {
    entries: checked.valid.length,
    pool_path: form.value.pool_path || DEFAULT_POOL_PATH,
    state_path: form.value.state_path || DEFAULT_STATE_PATH,
  };
  store.setPreflight("cloudflare_kv", {
    status: "ok",
    message: `Hotmail 池已保存，${checked.valid.length} 条邮箱`,
    checks: [],
  });
}

async function submitCurrentSource() {
  deploying.value = true;
  try {
    if (form.value.source === "hotmail_pool") {
      await saveHotmailPool();
    } else {
      await deployCfKv();
    }
  } finally {
    deploying.value = false;
  }
}

watch(form, () => {
  // form 只同步基础输入，不覆盖 deploy 成功后回写的 account/kv 字段
  const cur = (store.answers.cloudflare_kv ?? {}) as any;
  store.setAnswer("cloudflare_kv", {
    ...cur,
    ...normalizeFormForStore(),
  });
}, { deep: true });
</script>

<style scoped>
.source-switch {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.source-pill {
  background: transparent;
  border: 1px solid var(--border-strong);
  color: var(--fg-secondary);
  padding: 8px 12px;
  font: inherit;
  font-size: 12px;
  cursor: pointer;
  transition: all 80ms;
}

.source-pill:hover {
  border-color: var(--accent);
  color: var(--fg-primary);
  background: var(--bg-panel);
}

.source-pill.active {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--bg-panel);
}

.tf {
  display: grid;
  grid-template-columns: minmax(180px, max-content) minmax(0, 1fr);
  border: 1px solid var(--border);
  background: var(--bg-base);
  transition: border-color 80ms;
}

.tf:focus-within { border-color: var(--accent); }

.tf-tag {
  background: var(--bg-panel);
  color: var(--fg-tertiary);
  padding: 10px 12px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.04em;
  border-right: 1px solid var(--border);
  display: flex;
  align-items: flex-start;
  white-space: nowrap;
}

.tf-textarea {
  background: transparent;
  border: 0;
  padding: 10px 12px;
  color: var(--fg-primary);
  font: inherit;
  font-size: 13px;
  outline: none;
  resize: vertical;
  min-height: 120px;
  width: 100%;
}

.tf-textarea::placeholder { color: var(--fg-tertiary); opacity: 0.6; }

.kv-inline-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}

@media (max-width: 900px) {
  .tf { grid-template-columns: 1fr; }
  .tf-tag { border-right: 0; border-bottom: 1px solid var(--border); }
  .kv-inline-grid { grid-template-columns: 1fr; }
}
</style>
