<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import {
  cancelPasswordAudit,
  generatePasswordCandidates,
  getPasswordAudit,
  getSavedWifiPassword,
  startPasswordAudit
} from '../api'

// 找回密码只在这个弹窗的内存里处理：不写 localStorage，也不写服务器。
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  ssid: { type: String, default: '' },
  iface: { type: String, default: '' },
  networks: { type: Array, default: () => [] }
})
const emit = defineEmits(['update:modelValue', 'done'])

const selectedSSID = ref(props.ssid)
const useBuiltin = ref(true)
const wordText = ref('')
const uploadedWords = ref([])
const uploadName = ref('')
const max = ref(200)
const timeoutSec = ref(4)
const delayMs = ref(300)
const authorized = ref(false)

const readingSaved = ref(false)
const savedFound = ref(false)
const savedPassword = ref('')
const showSaved = ref(false)

const preview = ref([])
const previewTotal = ref(0)
const generating = ref(false)
const job = ref(null)
const resultPassword = ref('')
const showResult = ref(false)
let pollTimer = null

const running = computed(() => job.value?.state === 'running')
const progress = computed(() => {
  if (!job.value || !job.value.total) return 0
  return Math.min(100, Math.round((job.value.attempted / job.value.total) * 100))
})

function mask(value) {
  if (!value) return ''
  return '•'.repeat(Math.min(Math.max([...value].length, 4), 12))
}

// 上传与粘贴的解析规则一致：一行一个密码，CSV 取第一列，跳过注释和空行。
function parseWordText(text) {
  const lines = String(text || '').replace(/^\ufeff/, '').split(/\r?\n/)
  const seen = new Set()
  const words = []
  for (const raw of lines) {
    let line = raw.trim().replace(/^["']|["']$/g, '').trim()
    if (!line || line.startsWith('#')) continue
    const comma = line.indexOf(',')
    if (comma >= 0) line = line.slice(0, comma).trim()
    if (line && !seen.has(line)) {
      seen.add(line)
      words.push(line)
    }
    if (words.length >= 100000) break
  }
  return words
}

const sourceWords = computed(() => {
  const seen = new Set()
  const words = []
  for (const word of [...uploadedWords.value, ...parseWordText(wordText.value)]) {
    if (!seen.has(word)) {
      seen.add(word)
      words.push(word)
    }
  }
  return words
})

function candidateRequest() {
  return {
    ssid: selectedSSID.value,
    builtin: useBuiltin.value,
    words: sourceWords.value,
    max: max.value
  }
}

async function onUploadChange(file) {
  try {
    const raw = file.raw || file
    if (raw.size > 1024 * 1024) {
      ElMessage.error('密码列表不能超过 1 MB')
      return
    }
    const buffer = await raw.arrayBuffer()
    let text
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buffer)
    } catch (e) {
      // 中文 Windows 导出的列表常见 GB18030 编码。
      try {
        text = new TextDecoder('gb18030').decode(buffer)
      } catch (fallback) {
        text = new TextDecoder('utf-8').decode(buffer)
      }
    }
    uploadedWords.value = parseWordText(text)
    uploadName.value = raw.name
    preview.value = []
    previewTotal.value = 0
    ElMessage.success(`已读取 ${uploadedWords.value.length} 条候选`)
  } catch (e) {
    ElMessage.error('读取密码列表失败')
  }
}

function removeUpload() {
  uploadedWords.value = []
  uploadName.value = ''
  preview.value = []
  previewTotal.value = 0
}

async function readSaved() {
  if (!selectedSSID.value) {
    ElMessage.warning('请先选择或输入 SSID')
    return
  }
  readingSaved.value = true
  try {
    const data = await getSavedWifiPassword({ interface: props.iface, ssid: selectedSSID.value })
    savedFound.value = !!data?.found
    savedPassword.value = data?.password || ''
    showSaved.value = false
    if (!data?.found) ElMessage.info('本机没有保存这个网络的密码')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    readingSaved.value = false
  }
}

async function generatePreview() {
  if (!selectedSSID.value) {
    ElMessage.warning('请先选择或输入 SSID')
    return
  }
  generating.value = true
  try {
    const data = await generatePasswordCandidates(candidateRequest())
    preview.value = (data?.candidates || []).slice(0, 10)
    previewTotal.value = data?.total || 0
    if (!previewTotal.value) ElMessage.warning('没有可用候选，请勾选内置组合或添加密码列表')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    generating.value = false
  }
}

async function downloadCandidates() {
  if (!selectedSSID.value) {
    ElMessage.warning('请先选择或输入 SSID')
    return
  }
  try {
    const data = await generatePasswordCandidates(candidateRequest())
    const list = data?.candidates || []
    if (!list.length) {
      ElMessage.warning('没有可导出的候选')
      return
    }
    const blob = new Blob([list.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${selectedSSID.value}-candidates.txt`
    link.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error(e.message)
  }
}

function stopPolling() {
  if (pollTimer !== null) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

async function poll() {
  if (!job.value) return
  try {
    const latest = await getPasswordAudit(job.value.id)
    job.value = latest
    if (latest.state !== 'running') {
      stopPolling()
      if (latest.state === 'found') {
        resultPassword.value = latest.password || ''
        showResult.value = false
        ElMessage.success('已找到密码')
        emit('done')
      } else if (latest.state === 'not_found') {
        ElMessage.warning(`已尝试 ${latest.attempted} 个候选，仍未找到匹配密码`)
      } else if (latest.state === 'error') {
        ElMessage.error(latest.error || '找回失败')
      } else if (latest.state === 'canceled') {
        ElMessage.info('已停止尝试')
      }
    }
  } catch (e) {
    stopPolling()
    ElMessage.error(e.message)
  }
}

async function startAudit() {
  if (!authorized.value) {
    ElMessage.warning('请先确认你已获得授权')
    return
  }
  if (!selectedSSID.value) {
    ElMessage.warning('请先选择或输入 SSID')
    return
  }
  try {
    const generated = await generatePasswordCandidates(candidateRequest())
    if (!generated?.total) {
      ElMessage.warning('没有可用候选，请勾选内置组合或添加密码列表')
      return
    }
    const started = await startPasswordAudit({
      interface: props.iface || '',
      ssid: selectedSSID.value,
      builtin: useBuiltin.value,
      words: sourceWords.value,
      max: max.value,
      attempt_ms: timeoutSec.value * 1000,
      delay_ms: delayMs.value,
      authorized: true
    })
    job.value = started
    resultPassword.value = ''
    showResult.value = false
    stopPolling()
    pollTimer = setInterval(poll, 500)
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function stopAudit() {
  if (!job.value || !job.value.id) return
  try {
    await cancelPasswordAudit(job.value.id)
  } catch (e) {
    // 任务可能刚好结束，仍然停止本地轮询。
  }
  stopPolling()
  if (job.value) job.value = { ...job.value, state: 'canceled' }
}

async function copy(value) {
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success('已复制到剪贴板')
  } catch (e) {
    ElMessage.warning('复制失败，请手动选中密码')
  }
}

function resetState() {
  stopPolling()
  savedFound.value = false
  savedPassword.value = ''
  showSaved.value = false
  resultPassword.value = ''
  showResult.value = false
  job.value = null
  preview.value = []
  previewTotal.value = 0
  authorized.value = false
  readingSaved.value = false
  generating.value = false
}

watch(() => props.modelValue, value => {
  if (value) {
    selectedSSID.value = props.ssid || selectedSSID.value
  } else {
    if (running.value) stopAudit()
    resetState()
  }
})

onBeforeUnmount(() => {
  if (running.value) stopAudit()
  stopPolling()
})
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    title="找回 Wi-Fi 密码"
    width="640px"
    @update:model-value="value => emit('update:modelValue', value)"
  >
    <el-alert
      type="warning"
      :closable="false"
      title="仅用于你自己的网络或已获得授权的网络"
      description="在线尝试会串行逐个进行，每次几秒，可能持续很久；尝试期间当前 Wi-Fi 会短暂断开。密码不会保存到服务器或浏览器。"
      show-icon
    />

    <div class="recover-step">
      <h3 class="recover-step__title">1. 读取本机已保存的密码</h3>
      <div class="recover-row">
        <el-select
          v-model="selectedSSID"
          filterable
          allow-create
          default-first-option
          placeholder="选择或输入 SSID"
          class="recover-row__select"
        >
          <el-option v-for="net in networks" :key="net.ssid" :label="net.ssid" :value="net.ssid" />
        </el-select>
        <el-button :loading="readingSaved" :disabled="!selectedSSID" @click="readSaved">读取已保存密码</el-button>
      </div>
      <div v-if="savedFound" class="recover-result">
        <span class="mono">{{ showSaved ? savedPassword : mask(savedPassword) }}</span>
        <el-button link size="small" @click="showSaved = !showSaved">{{ showSaved ? '隐藏' : '显示' }}</el-button>
        <el-button link size="small" :disabled="!savedPassword" @click="copy(savedPassword)">复制</el-button>
        <span v-if="!savedPassword" class="text-dim">该网络为开放网络或未保存密钥</span>
      </div>
    </div>

    <el-divider />

    <div class="recover-step">
      <h3 class="recover-step__title">2. 生成候选密码并小批量尝试</h3>
      <div class="recover-options">
        <el-checkbox v-model="useBuiltin">内置常见组合（约 200 个）</el-checkbox>
        <div class="recover-options__number">上限 <el-input-number v-model="max" :min="1" :max="5000" size="small" /></div>
        <div class="recover-options__number">每次超时 <el-input-number v-model="timeoutSec" :min="1" :max="30" size="small" /> 秒</div>
        <div class="recover-options__number">间隔 <el-input-number v-model="delayMs" :min="0" :max="5000" :step="100" size="small" /> 毫秒</div>
      </div>

      <div class="recover-row recover-row--top">
        <el-upload
          :auto-upload="false"
          :show-file-list="false"
          accept=".txt,.csv"
          :on-change="onUploadChange"
        >
          <el-button size="small">上传密码列表</el-button>
        </el-upload>
        <span v-if="uploadName" class="text-dim">
          {{ uploadName }}（{{ uploadedWords.length }} 条）
          <el-button link size="small" type="danger" @click="removeUpload">移除</el-button>
        </span>
        <span v-else class="text-dim">支持 UTF-8 / GB18030，每行一个或 CSV 第一列，最大 1 MB</span>
      </div>

      <el-input
        v-model="wordText"
        type="textarea"
        :rows="3"
        placeholder="也可以直接粘贴候选密码，每行一个；# 开头为注释"
      />

      <div class="recover-preview">
        <el-button size="small" :loading="generating" @click="generatePreview">生成预览</el-button>
        <el-button size="small" @click="downloadCandidates">下载候选列表</el-button>
        <span class="text-dim">共 {{ previewTotal }} 个候选</span>
        <div v-if="preview.length" class="recover-preview__list mono">
          <span v-for="(pwd, index) in preview" :key="index">{{ mask(pwd) }}</span>
          <span v-if="previewTotal > preview.length">…</span>
        </div>
      </div>

      <div class="recover-progress" v-if="job || resultPassword">
        <el-progress :percentage="progress" :status="job?.state === 'found' ? 'success' : undefined" />
        <div class="text-dim">
          已尝试 {{ job?.attempted || 0 }} / {{ job?.total || 0 }}
          <span v-if="running && job?.current"> · 当前 {{ job.current }}</span>
        </div>
        <div v-if="resultPassword" class="recover-result">
          <span class="mono">{{ showResult ? resultPassword : mask(resultPassword) }}</span>
          <el-button link size="small" @click="showResult = !showResult">{{ showResult ? '隐藏' : '显示' }}</el-button>
          <el-button link size="small" @click="copy(resultPassword)">复制</el-button>
        </div>
      </div>

      <el-checkbox v-model="authorized" class="recover-authorize">
        我确认这是自己的网络或已获得授权，可以逐个尝试密码
      </el-checkbox>
      <div class="recover-actions">
        <el-button type="primary" :loading="running" :disabled="!authorized || running" @click="startAudit">
          开始尝试
        </el-button>
        <el-button :disabled="!running" @click="stopAudit">停止</el-button>
      </div>
    </div>
  </el-dialog>
</template>

<style scoped>
.recover-step__title {
  margin: 0 0 10px;
  font-size: 14px;
  font-weight: 600;
}

.recover-row {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  flex-wrap: wrap;
}

.recover-row--top {
  align-items: flex-start;
  margin: 10px 0;
}

.recover-row__select {
  width: 260px;
}

.recover-options {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-2) var(--space-3);
}

.recover-options__number {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--color-text-secondary);
}

.recover-preview {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  flex-wrap: wrap;
  margin-top: 10px;
}

.recover-preview__list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  width: 100%;
  font-size: 12px;
  color: var(--color-text-dim);
}

.recover-progress {
  margin-top: 12px;
}

.recover-result {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
}

.recover-authorize {
  display: flex;
  margin-top: 12px;
}

.recover-actions {
  display: flex;
  gap: var(--space-2);
  margin-top: 10px;
}
</style>
