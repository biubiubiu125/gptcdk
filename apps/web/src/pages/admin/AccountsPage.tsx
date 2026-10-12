import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  App as AntApp,
  Button,
  Checkbox,
  Collapse,
  Dropdown,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Radio,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Upload,
} from 'antd';
import type { TableProps } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  CopyOutlined,
  DownloadOutlined,
  DownOutlined,
  InboxOutlined,
  PlusOutlined,
  ReloadOutlined,
  SyncOutlined,
} from '@ant-design/icons';

import {
  batchDeleteAccounts,
  retagAccounts,
  copyCard,
  downloadBlob,
  downloadText,
  errorMessage,
  exportAccountsBlob,
  extractProxyReady,
  importAccounts,
  listAccounts,
  listCreditTiers,
  listExtractJobs,
  stopExtractJob,
  refreshAccountStatus,
  updateAccount,
  MAIL_CREDITS_PER_TIER,
} from '../../api/client';
import {
  DELIVER_FORMAT_OPTIONS,
  type AccountListQuery,
  AccountRow,
  AccountSortField,
  AccountSummary,
  BanStatus,
  CreditTier,
  DeliverFormat,
  ExtractJobRow,
  ImportFile,
  ImportResponse,
  RedeemStatus,
  RefreshFilterPayload,
  RefreshStatusRequest,
  RefreshStatusResponse,
  RefreshTarget,
  SortOrder,
} from '../../api/types';
import CopyButton, { copyToClipboard } from '../../components/CopyButton';
import MailboxModal from '../../components/MailboxModal';
import { useLatestRequest } from '../../hooks/useLatestRequest';
import { copyCardKeys, reportCardCopy, type CardCopyScope } from '../../utils/cardCopy';
import {
  BAN_STATUS_META,
  BAN_STATUS_OPTIONS,
  CREDIT_STATUS_META,
  REDEEM_STATUS_META,
  REDEEM_STATUS_OPTIONS,
  formatBytes,
  formatCredits,
  formatDateTime,
  formatNumber,
} from '../../utils/format';

const { TextArea } = Input;

const SUBSCRIPTION_TAG_OPTIONS = [
  { value: 'Plus' },
  { value: 'Pro' },
  { value: 'Pro5x' },
  { value: 'Pro10x' },
  { value: 'Pro25x' },
  { value: '20X' },
  { value: '5X Team' },
];

function subscriptionTagError(value: string): string {
  const tag = value.trim();
  if (!tag) return '';
  if (tag.length > 32 || /[\\/]/.test(tag) || tag.includes('..')) return '标记只能是 32 字以内的短名称，不能包含斜杠';
  return '';
}

function resolveSubscriptionTag(selected?: string, custom?: string): string {
  return String(custom || '').trim() || String(selected || '').trim();
}

const PAGE_SIZE_DEFAULT = 20;
const IMPORT_MAX_FILE_SIZE = 20 * 1024 * 1024;
/** 待定档（额度还没从邮件里定出来）在筛选器里的哨兵值 */
const PENDING_CREDITS = 0;

const EMPTY_SUMMARY: AccountSummary = {
  total: 0,
  unredeemed: 0,
  redeemed: 0,
  banned: 0,
  invalid: 0,
  unknown: 0,
  pending: 0,
  byCredits: [],
};

const SORT_PRESETS: Array<{ value: string; label: string; field: AccountSortField; order: SortOrder }> = [
  { value: 'createdAt-descend', label: '导入时间↓', field: 'createdAt', order: 'descend' },
  { value: 'createdAt-ascend', label: '导入时间↑', field: 'createdAt', order: 'ascend' },
  { value: 'credits-descend', label: '额度↓', field: 'credits', order: 'descend' },
  { value: 'credits-ascend', label: '额度↑', field: 'credits', order: 'ascend' },
  { value: 'id-descend', label: '编号↓', field: 'id', order: 'descend' },
  { value: 'id-ascend', label: '编号↑', field: 'id', order: 'ascend' },
];

const EXPORT_ITEMS = DELIVER_FORMAT_OPTIONS.map((item) => ({ key: item.value, label: item.label }));

interface AccountFilters {
  credits: number[];
  banStatus: BanStatus[];
  redeemStatus: RedeemStatus[];
  keyword: string;
  sortField?: AccountSortField;
  sortOrder?: SortOrder;
}

const INITIAL_FILTERS: AccountFilters = {
  credits: [],
  banStatus: [],
  redeemStatus: [],
  keyword: '',
};

/* ==================================================================== *
 * 导入账号弹窗
 * ==================================================================== */

interface ImportFormValues {
  prefix: string;
  remark?: string;
  skipDuplicate: boolean;
  subscriptionTag: string;
  customSubscriptionTag?: string;
  proxy?: string;
  rememberProxy?: boolean;
  useRememberedProxy?: boolean;
  keyGroups: number;
  keyLength: number;
}

interface LocalFile extends ImportFile {
  size: number;
}

interface ImportAccountsModalProps {
  open: boolean;
  tiers: CreditTier[];
  onClose: () => void;
  onImported: (result: ImportResponse) => void;
}

/**
 * 导入弹窗。
 *
 * 必须选择订阅标记。账密行会异步登录提取；JSON 直接入库，但 5X Team 必须已是空间 token。
 */
function ImportAccountsModal({ open, tiers, onClose, onImported }: ImportAccountsModalProps) {
  const { message } = AntApp.useApp();
  const [form] = Form.useForm<ImportFormValues>();

  const [tab, setTab] = useState<'paste' | 'upload'>('paste');
  const [content, setContent] = useState('');
  const [files, setFiles] = useState<LocalFile[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<ImportResponse | null>(null);
  const [jobs, setJobs] = useState<ExtractJobRow[]>([]);
  const [proxyReady, setProxyReady] = useState(false);

  const loadJobs = useCallback(async () => {
    try {
      const data = await listExtractJobs();
      setJobs(data.items);
    } catch {
      /* 提取任务列表失败时不打断导入 */
    }
  }, []);

  useEffect(() => {
    if (!open) {
      setResult(null);
      setContent('');
      setFiles([]);
      setTab('paste');
      setJobs([]);
      return;
    }
    void extractProxyReady().then((data) => setProxyReady(data.ready)).catch(() => setProxyReady(false));
    void loadJobs();
    const timer = window.setInterval(() => void loadJobs(), 3000);
    return () => window.clearInterval(timer);
  }, [loadJobs, open]);

  const tierHint = useMemo(() => {
    const values = tiers
      .filter((item) => item.credits > 0)
      .map((item) => item.credits)
      .slice(0, 8);
    return values.length > 0 ? values.join(' / ') : '（取件命中后自动生成）';
  }, [tiers]);

  const handleFiles = useCallback(
    async (incoming: File[]) => {
      for (const file of incoming) {
        if (file.size > IMPORT_MAX_FILE_SIZE) {
          void message.error(`${file.name} 超过 20MB 限制`);
          continue;
        }
        try {
          const text = await file.text();
          setFiles((previous) =>
            previous.some((item) => item.name === file.name)
              ? previous
              : [...previous, { name: file.name, size: file.size, content: text }],
          );
        } catch {
          void message.error(`${file.name} 读取失败`);
        }
      }
    },
    [message],
  );

  const handleSubmit = async () => {
    let values: ImportFormValues;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }

    const trimmed = content.trim();
    if (!trimmed && files.length === 0) {
      void message.warning('请粘贴 JSON 内容或上传文件');
      return;
    }

    setSubmitting(true);
    try {
      const response = await importAccounts({
        content: trimmed || undefined,
        files: files.length > 0 ? files.map(({ name, content: text }) => ({ name, content: text })) : undefined,
        prefix: values.prefix?.trim() || 'CARD',
        source: tab,
        remark: values.remark?.trim() || undefined,
        skipDuplicate: values.skipDuplicate,
        keyGroups: values.keyGroups,
        keyLength: values.keyLength,
        subscriptionTag: resolveSubscriptionTag(values.subscriptionTag, values.customSubscriptionTag),
        proxy: values.proxy,
        rememberProxy: values.rememberProxy,
        useRememberedProxy: values.useRememberedProxy,
      });
      setResult(response);
      void loadJobs();
      void message.success(`导入完成：成功 ${response.imported} 个，排队 ${response.queued ?? 0} 个`);
      onImported(response);
    } catch (error) {
      void message.error(errorMessage(error));
    } finally {
      setSubmitting(false);
    }
  };

  const sampleColumns: ColumnsType<ImportResponse['samples'][number]> = [
    { title: '编号', dataIndex: 'id', key: 'id', width: 90 },
    {
      title: '账号名',
      dataIndex: 'name',
      key: 'name',
      ellipsis: true,
      render: (value: string) => <span title={value}>{value}</span>,
    },
    {
      title: '卡密',
      dataIndex: 'cardKey',
      key: 'cardKey',
      width: 260,
      render: (value: string) => (
        <span className="table-key" title={value}>
          {value}
        </span>
      ),
    },
  ];

  const copyAllCards = async () => {
    if (!result) return;
    const ok = await copyToClipboard(result.cards.join('\n'));
    if (ok) void message.success(`已复制 ${result.cards.length} 张卡密`);
    else void message.warning('复制失败，请手动复制');
  };

  const copyAllResults = async () => {
    if (!result) return;
    const text = result.samples.map((item) => `${item.name}----${item.cardKey}`).join('\n');
    const ok = await copyToClipboard(text);
    if (ok) void message.success('已复制全部结果');
    else void message.warning('复制失败，请手动复制');
  };

  return (
    <Modal
      open={open}
      width={720}
      title="导入账号"
      okText="开始导入"
      cancelText="关闭"
      confirmLoading={submitting}
      onOk={() => {
        void handleSubmit();
      }}
      onCancel={onClose}
      destroyOnClose
    >
      <Tabs
        activeKey={tab}
        onChange={(key) => setTab(key as 'paste' | 'upload')}
        items={[
          {
            key: 'paste',
            label: '粘贴 JSON',
            children: (
              <TextArea
                rows={12}
                spellCheck={false}
                style={{ fontFamily: 'ui-monospace, Consolas, monospace', fontSize: 12.5, resize: 'none' }}
                placeholder='{ "accounts": [ { "platform": "openai", "credentials": { "email": "abc@outlook.com", "access_token": "..." } } ] }'
                value={content}
                onChange={(event) => setContent(event.target.value)}
              />
            ),
          },
          {
            key: 'upload',
            label: '上传文件',
            children: (
              <div>
                <Upload.Dragger
                  multiple
                  showUploadList={false}
                  accept=".json,.txt,.jsonl"
                  beforeUpload={(file) => {
                    void handleFiles([file]);
                    return false;
                  }}
                >
                  <p className="ant-upload-drag-icon">
                    <InboxOutlined />
                  </p>
                  <p className="ant-upload-text">点击或拖拽文件到此处上传</p>
                  <p className="ant-upload-hint">支持 .json / .txt / .jsonl，单文件最大 20MB</p>
                </Upload.Dragger>

                {files.length > 0 ? (
                  <div className="import-files">
                    {files.map((file) => (
                      <div className="import-file-row" key={file.name}>
                        <span className="import-file-row__name" title={file.name}>
                          {file.name}
                        </span>
                        <span className="import-file-row__size">{formatBytes(file.size)}</span>
                        <Button
                          type="link"
                          size="small"
                          onClick={() =>
                            setFiles((previous) => previous.filter((item) => item.name !== file.name))
                          }
                        >
                          移除
                        </Button>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ),
          },
        ]}
      />

      <Form
        form={form}
        layout="vertical"
        style={{ marginTop: 8 }}
        initialValues={{
          prefix: 'CARD',
          skipDuplicate: true,
          subscriptionTag: 'Plus',
          keyGroups: 3,
          keyLength: 5,
        }}
      >
        <div className="import-grid">
          <Form.Item name="subscriptionTag" label="订阅标记" rules={[{ required: true, message: '请选择订阅标记' }]}>
            <Select options={SUBSCRIPTION_TAG_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="customSubscriptionTag"
            label="自定义短标记"
            extra="填写后优先使用。32 字以内，不能包含斜杠。5X Team 仍按空间 token 核对。"
            rules={[{ validator: async (_, value) => {
              const reason = subscriptionTagError(String(value || ''));
              if (reason) throw new Error(reason);
            } }]}
          >
            <Input maxLength={32} placeholder="例如 Pro5x" />
          </Form.Item>
          <Form.Item name="proxy" label="提取 SOCKS 代理">
            <Input.Password placeholder="socks5://user:pass@host:port" autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="useRememberedProxy" label={proxyReady ? '使用已记住代理（已保存）' : '使用已记住代理'} valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="rememberProxy" label="记住本次代理" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="prefix" label="卡密前缀">
            <Input placeholder="CARD" />
          </Form.Item>
          <Form.Item name="remark" label="批次备注">
            <Input placeholder="例如 2月批次" />
          </Form.Item>
          <Form.Item name="keyGroups" label="卡密段数">
            <InputNumber style={{ width: '100%' }} min={2} max={5} precision={0} />
          </Form.Item>
          <Form.Item name="keyLength" label="每段长度">
            <InputNumber style={{ width: '100%' }} min={3} max={8} precision={0} />
          </Form.Item>
          <Form.Item name="skipDuplicate" label="跳过重复账号" valuePropName="checked">
            <Switch />
          </Form.Item>
        </div>

        <div className="import-note">
          5X Team 的 JSON 必须已经是空间 token；没有套餐声明的个人文件不会入库。账密行按 `邮箱----密码----2FA` 异步提取，必须提供 SOCKS 代理。
          已标记账号按标记售卖，不再按邮箱额度定档。当前已有档位：{tierHint}
        </div>
      </Form>

      <Table
        rowKey="id"
        size="small"
        style={{ marginTop: 12 }}
        pagination={false}
        dataSource={jobs.slice(0, 20)}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无提取任务" /> }}
        columns={[
          { title: '邮箱', dataIndex: 'email', ellipsis: true },
          {
            title: '状态',
            dataIndex: 'status',
            width: 90,
            render: (status: string) => ({ queued: '排队', running: '提取中', retrying: '重试中', succeeded: '已入库', failed: '失败', stopped: '已停止' }[status] || status),
          },
          { title: '说明', dataIndex: 'message', ellipsis: true },
          {
            title: '',
            width: 72,
            render: (_value, job) => ['queued', 'running', 'retrying'].includes(job.status) ? (
              <Button
                type="link"
                size="small"
                onClick={() => {
                  void stopExtractJob(job.id).then(() => loadJobs()).catch((error) => message.error(errorMessage(error)));
                }}
              >
                停止
              </Button>
            ) : null,
          },
        ]}
      />

      {result ? (
        <div className="import-result">
          <div className="import-result__stats">
            <span>
              导入 <b>{result.imported}</b> 个
            </span>
            <span>
              跳过 <b>{result.skipped}</b> 个
            </span>
            <span>
              失败 <b>{result.failed}</b> 个
            </span>
            <span>
              待定档 <b>{formatNumber(result.pending)}</b> 个
            </span>
            <span>
              批次 <b className="mono">{result.batchId}</b>
            </span>
          </div>

          <Space wrap style={{ marginBottom: 10 }}>
            <Button size="small" onClick={() => void copyAllCards()}>
              复制全部卡密
            </Button>
            <Button size="small" onClick={() => void copyAllResults()}>
              复制全部结果
            </Button>
          </Space>

          <Table
            rowKey="id"
            size="small"
            columns={sampleColumns}
            dataSource={result.samples.slice(0, 50)}
            pagination={false}
            scroll={{ y: 240 }}
            locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有生成记录" /> }}
          />

          {result.errors.length > 0 ? (
            <Collapse
              ghost
              style={{ marginTop: 10 }}
              items={[
                {
                  key: 'errors',
                  label: <span style={{ color: '#D9534F' }}>失败明细（{result.errors.length}）</span>,
                  children: (
                    <div className="import-errors gptcdk-scroll">
                      {result.errors.map((item, index) => (
                        <div className="import-error-row" key={`${item.index}-${index}`}>
                          <span className="import-error-row__index">#{item.index}</span>
                          <span className="import-error-row__name">{item.name || '—'}</span>
                          <span className="import-error-row__reason">{item.reason}</span>
                        </div>
                      ))}
                    </div>
                  ),
                },
              ]}
            />
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}

/* ==================================================================== *
 * 刷新状态弹窗
 * ==================================================================== */

interface RefreshStatusModalProps {
  open: boolean;
  selectedIds: number[];
  filter: RefreshFilterPayload;
  total: number;
  onClose: () => void;
  onDone: () => void;
}

function RefreshStatusModal({
  open,
  selectedIds,
  filter,
  total,
  onClose,
  onDone,
}: RefreshStatusModalProps) {
  const { message } = AntApp.useApp();
  const hasSelection = selectedIds.length > 0;

  const [refreshBan, setRefreshBan] = useState(true);
  const [refreshRedeem, setRefreshRedeem] = useState(true);
  const [scope, setScope] = useState<'selected' | 'filter'>('filter');
  const [limit, setLimit] = useState(100);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RefreshStatusResponse | null>(null);

  useEffect(() => {
    if (!open) return;
    setResult(null);
    setRunning(false);
    setScope(hasSelection ? 'selected' : 'filter');
  }, [open, hasSelection]);

  const handleRun = async () => {
    const targets: RefreshTarget[] = [];
    if (refreshBan) targets.push('ban');
    if (refreshRedeem) targets.push('redeem');

    if (targets.length === 0) {
      void message.warning('请至少选择一个刷新目标');
      return;
    }

    setRunning(true);
    try {
      if (targets.length > 0) {
        const payload: RefreshStatusRequest =
          scope === 'selected' && hasSelection
            ? { ids: selectedIds, targets }
            : { filter, limit, targets };
        const response = await refreshAccountStatus(payload);
        setResult(response);
        void message.success(`刷新完成：处理 ${response.processed} / ${response.requested}`);
      }

      onDone();
    } catch (error) {
      void message.error(errorMessage(error));
    } finally {
      setRunning(false);
    }
  };

  return (
    <Modal
      open={open}
      width={560}
      title="刷新状态"
      okText="开始执行"
      cancelText="关闭"
      confirmLoading={running}
      onOk={() => {
        void handleRun();
      }}
      onCancel={onClose}
      destroyOnClose
    >
      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <div>
          <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 8 }}>执行目标</div>
          <Space direction="vertical" size={4}>
            <Checkbox checked={refreshBan} onChange={(event) => setRefreshBan(event.target.checked)}>
              刷新封禁状态
            </Checkbox>
            <Checkbox
              checked={refreshRedeem}
              onChange={(event) => setRefreshRedeem(event.target.checked)}
            >
              检查账号凭据
            </Checkbox>
          </Space>
        </div>

        <div>
          <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 8 }}>范围</div>
          <Radio.Group
            value={scope}
            onChange={(event) => setScope(event.target.value as 'selected' | 'filter')}
          >
            <Space direction="vertical" size={6}>
              {hasSelection ? (
                <Radio value="selected">选中的 {selectedIds.length} 条</Radio>
              ) : null}
              <Radio value="filter">
                按当前筛选条件（每轮最多 {limit} 条，共 {formatNumber(total)} 条）
              </Radio>
            </Space>
          </Radio.Group>

          {scope === 'filter' ? (
            <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 12.5, color: '#6B7A74' }}>单轮处理条数</span>
              <InputNumber
                min={1}
                max={500}
                precision={0}
                value={limit}
                onChange={(value) => setLimit(typeof value === 'number' ? value : 100)}
                style={{ width: 120 }}
              />
            </div>
          ) : null}
        </div>

        {running ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#6B7A74' }}>
            <Spin size="small" />
            正在执行…
          </div>
        ) : null}

        {result ? (
          <div className="admin-card" style={{ background: '#FAFBF9' }}>
            <div style={{ fontSize: 12.5, color: '#2C3A35' }}>
              请求 {result.requested} 条 · 实际处理 {result.processed} 条
            </div>
            {result.ban ? (
              <div style={{ marginTop: 6, fontSize: 12.5, color: '#6B7A74' }}>
                封禁：已封禁 {result.ban.banned} · 正常 {result.ban.normal} · 凭据失效{' '}
                {result.ban.invalid} · 失败 {result.ban.failed}
              </div>
            ) : null}
            {result.redeem ? (
              <div style={{ marginTop: 6, fontSize: 12.5, color: '#6B7A74' }}>
                兑换：已兑换 {result.redeem.redeemed} · 未兑换 {result.redeem.unredeemed} · 失败{' '}
                {result.redeem.failed}
              </div>
            ) : null}
            {result.items.some((item) => item.error) ? (
              <div style={{ marginTop: 8, fontSize: 12.5, color: '#8A4B3A' }}>
                {result.items
                  .filter((item) => item.error)
                  .map((item) => (
                    <div key={item.id}>
                      {item.name || item.id}：{item.error}
                    </div>
                  ))}
              </div>
            ) : null}
            {result.items.some((item) => item.unsavedCredential) ? (
              <Button
                style={{ marginTop: 8 }}
                icon={<DownloadOutlined />}
                onClick={() => {
                  const payload = result.items
                    .filter((item) => item.unsavedCredential)
                    .map((item) => ({
                      id: item.id,
                      name: item.name || null,
                      ...item.unsavedCredential,
                    }));
                  downloadText(JSON.stringify(payload, null, 2), `unsaved-credentials-${Date.now()}.json`);
                }}
              >
                下载未落库凭据
              </Button>
            ) : null}
          </div>
        ) : null}
      </Space>
    </Modal>
  );
}

/* ==================================================================== *
 * 账号列表页
 * ==================================================================== */

/**
 * 后台 · 账号列表（筛选 + 排序 + 导入 + 刷新状态 + 取件）。
 */
export default function AccountsPage() {
  const { message } = AntApp.useApp();
  const { begin, isCurrent, invalidate } = useLatestRequest();

  const [filters, setFilters] = useState<AccountFilters>(INITIAL_FILTERS);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZE_DEFAULT);

  const [rows, setRows] = useState<AccountRow[]>([]);
  const [total, setTotal] = useState(0);
  const [summary, setSummary] = useState<AccountSummary>(EMPTY_SUMMARY);
  const [loading, setLoading] = useState(false);

  const [tiers, setTiers] = useState<CreditTier[]>([]);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [extraColumns, setExtraColumns] = useState<string[]>([]);

  const [importOpen, setImportOpen] = useState(false);
  const [refreshOpen, setRefreshOpen] = useState(false);
  const [remarkTarget, setRemarkTarget] = useState<AccountRow | null>(null);
  const [mailboxAccount, setMailboxAccount] = useState<AccountRow | null>(null);
  const [remarkSaving, setRemarkSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [retagOpen, setRetagOpen] = useState(false);
  const [retagging, setRetagging] = useState(false);
  const [retagForm] = Form.useForm<{ subscriptionTag?: string; customSubscriptionTag?: string }>();
  const [copyingKeys, setCopyingKeys] = useState(false);
  const [remarkForm] = Form.useForm<{ remark?: string }>();

  const loadTiers = useCallback(async () => {
    try {
      const items = await listCreditTiers();
      setTiers(items);
    } catch {
      /* 档位接口不可用时回落到 summary.byCredits */
    }
  }, []);

  useEffect(() => {
    void loadTiers();
  }, [loadTiers]);

  const query = useMemo<AccountListQuery>(
    () => ({
      page,
      pageSize,
      keyword: filters.keyword || undefined,
      credits: filters.credits.length > 0 ? filters.credits : undefined,
      banStatus: filters.banStatus.length > 0 ? filters.banStatus : undefined,
      redeemStatus: filters.redeemStatus.length > 0 ? filters.redeemStatus : undefined,
      sortField: filters.sortField,
      sortOrder: filters.sortOrder,
    }),
    [filters, page, pageSize],
  );

  const load = useCallback(async () => {
    const request = begin();
    setLoading(true);
    try {
      const response = await listAccounts(query);
      if (!isCurrent(request)) return;
      setRows(response.items ?? []);
      setTotal(response.total ?? 0);
      setSummary(response.summary ?? EMPTY_SUMMARY);
    } catch (error) {
      if (!isCurrent(request)) return;
      void message.error(errorMessage(error));
      setRows([]);
      setTotal(0);
    } finally {
      if (isCurrent(request)) setLoading(false);
    }
  }, [begin, isCurrent, message, query]);

  useEffect(() => {
    void load();
    return invalidate;
  }, [invalidate, load]);

  const creditSelectOptions = useMemo(() => {
    const options =
      tiers.length > 0
        ? tiers.map((item) => ({ value: item.credits, label: item.label || formatCredits(item.credits) }))
        : summary.byCredits.map((item) => ({ value: item.credits, label: formatCredits(item.credits) }));
    const known = new Set(options.map((item) => item.value));
    if ((summary.pending > 0 || known.has(PENDING_CREDITS)) && !known.has(PENDING_CREDITS)) {
      options.unshift({ value: PENDING_CREDITS, label: '待定档' });
    }
    return options.map((item) =>
      item.value === PENDING_CREDITS ? { ...item, label: '待定档' } : item,
    );
  }, [summary.byCredits, summary.pending, tiers]);

  const sortValue = filters.sortField && filters.sortOrder ? `${filters.sortField}-${filters.sortOrder}` : undefined;

  const resetFilters = () => {
    setFilters(INITIAL_FILTERS);
    setPage(1);
  };

  const handleCopyCard = useCallback(
    async (record: AccountRow) => {
      try {
        const response = await copyCard(record.id);
        const ok = await copyToClipboard(response.cardKey || record.cardKey);
        if (ok) void message.success('卡密已复制');
        else void message.warning('剪贴板不可用，请手动复制');

        if (response.cardKey && response.cardKey !== record.cardKey) {
          setRows((previous) =>
            previous.map((item) =>
              item.id === record.id ? { ...item, cardKey: response.cardKey } : item,
            ),
          );
        }
      } catch (error) {
        void message.error(errorMessage(error));
      }
    },
    [message],
  );

  const handleCopyEmail = useCallback(
    async (record: AccountRow) => {
      const value = record.email || record.name;
      const ok = await copyToClipboard(value);
      if (ok) void message.success('邮箱已复制');
      else void message.warning('剪贴板不可用，请手动复制');
    },
    [message],
  );

  const addToDeleteSelection = useCallback(
    (id: number) => {
      setSelectedIds((previous) => (previous.includes(id) ? previous : [...previous, id]));
      void message.success('已加入待删除列表，点击「批量删除」执行');
    },
    [message],
  );

  const handleRetag = async () => {
    const values = await retagForm.validateFields();
    const tag = resolveSubscriptionTag(values.subscriptionTag, values.customSubscriptionTag);
    const reason = subscriptionTagError(tag);
    if (!tag || reason) {
      void message.error(reason || '请选择订阅标记');
      return;
    }
    setRetagging(true);
    try {
      const response = await retagAccounts(selectedIds, tag);
      void message.success(`已更新 ${response.updated} 个${response.rejected?.length ? `，${response.rejected.length} 个未通过` : ''}`);
      setRetagOpen(false);
      retagForm.resetFields();
      setSelectedIds([]);
      await load();
    } catch (error) {
      void message.error(errorMessage(error));
    } finally {
      setRetagging(false);
    }
  };

  const handleBatchDelete = async () => {
    if (selectedIds.length === 0) return;
    setDeleting(true);
    try {
      const response = await batchDeleteAccounts(selectedIds);
      void message.success(`已删除 ${response.deleted ?? 0} 个账号`);
      setSelectedIds([]);
      await load();
    } catch (error) {
      void message.error(errorMessage(error));
    } finally {
      setDeleting(false);
    }
  };

  /** 批量复制卡密：勾选账号 / 当前页 / 当前筛选全部（跨分页，走服务端拼接） */
  const handleCopyKeys = async (scope: CardCopyScope) => {
    const ids = scope === 'selected' ? selectedIds : scope === 'page' ? rows.map((row) => row.id) : [];
    if (scope === 'selected' && ids.length === 0) {
      void message.warning('请先勾选要复制的账号');
      return;
    }
    if (scope === 'page' && ids.length === 0) {
      void message.warning('当前页没有账号');
      return;
    }

    setCopyingKeys(true);
    try {
      const outcome = await copyCardKeys({
        ids: ids.length > 0 ? ids : undefined,
        filter:
          scope === 'filtered'
            ? {
                keyword: filters.keyword || undefined,
                credits: filters.credits.length > 0 ? filters.credits : undefined,
                banStatus: filters.banStatus.length > 0 ? filters.banStatus : undefined,
                redeemStatus: filters.redeemStatus.length > 0 ? filters.redeemStatus : undefined,
              }
            : undefined,
      });
      reportCardCopy(outcome, message, scope);
    } catch (error) {
      void message.error(errorMessage(error));
    } finally {
      setCopyingKeys(false);
    }
  };

  const copyKeyMenuItems = [
    {
      key: 'selected',
      label: `复制选中卡密（${selectedIds.length}）`,
      disabled: selectedIds.length === 0,
    },
    { key: 'page', label: `复制本页卡密（${rows.length}）`, disabled: rows.length === 0 },
    { key: 'filtered', label: `复制筛选结果全部（${total}）`, disabled: total === 0 },
  ];

  const handleExport = async (format: DeliverFormat) => {
    try {
      const { blob, filename } = await exportAccountsBlob({
        format,
        filter: {
          credits: filters.credits.length > 0 ? filters.credits : undefined,
          banStatus: filters.banStatus.length > 0 ? filters.banStatus : undefined,
          redeemStatus: filters.redeemStatus.length > 0 ? filters.redeemStatus : undefined,
          keyword: filters.keyword || undefined,
        },
        includeCardKey: true,
        filename: `accounts-${format}`,
      });
      downloadBlob(blob, filename);
      void message.success('导出已开始');
    } catch (error) {
      void message.error(errorMessage(error));
    }
  };

  const submitRemark = async () => {
    if (!remarkTarget) return;
    let values: { remark?: string };
    try {
      values = await remarkForm.validateFields();
    } catch {
      return;
    }

    setRemarkSaving(true);
    try {
      // 额度不在这里改：档位由邮箱取件命中关键字自动得出
      await updateAccount(remarkTarget.id, { remark: values.remark ?? '' });
      void message.success('已保存');
      setRemarkTarget(null);
      await load();
    } catch (error) {
      void message.error(errorMessage(error));
    } finally {
      setRemarkSaving(false);
    }
  };

  const sortOrderFor = (field: AccountSortField): SortOrder | null =>
    filters.sortField === field ? filters.sortOrder ?? null : null;

  const columns = useMemo<ColumnsType<AccountRow>>(() => {
    const core: ColumnsType<AccountRow> = [
      {
        title: '编号',
        dataIndex: 'id',
        key: 'id',
        width: 80,
        sorter: true,
        sortOrder: sortOrderFor('id'),
      },
      {
        title: '账号名',
        dataIndex: 'name',
        key: 'name',
        width: 240,
        sorter: true,
        sortOrder: sortOrderFor('name'),
        render: (_, record) => (
          <div style={{ minWidth: 0 }}>
            <div className="ellipsis" title={record.name}>
              {record.name}
            </div>
            {record.email && record.email !== record.name ? (
              <div className="table-sub ellipsis" title={record.email}>
                {record.email}
              </div>
            ) : null}
          </div>
        ),
      },
      {
        title: '额度',
        dataIndex: 'credits',
        key: 'credits',
        width: 130,
        sorter: true,
        sortOrder: sortOrderFor('credits'),
        render: (value: number, record) => {
          const pending = record.creditStatus === 'pending' || !(value > 0);
          if (pending) {
            return (
              <Tooltip title="额度来自邮箱取件命中的额度关键字；还没命中时为待定档，不进兑换池">
                <Tag color={CREDIT_STATUS_META.pending.color}>
                  {CREDIT_STATUS_META.pending.label}
                </Tag>
              </Tooltip>
            );
          }
          return (
            <Tooltip title={`邮件已命中 ${value * MAIL_CREDITS_PER_TIER} credits`}>
              <Tag color="green">{formatCredits(value)}</Tag>
            </Tooltip>
          );
        },
      },
      {
        title: '卡密',
        dataIndex: 'cardKey',
        key: 'cardKey',
        width: 280,
        sorter: true,
        sortOrder: sortOrderFor('cardKey'),
        render: (value: string) => (
          <Space size={2}>
            <span className="table-key" title={value}>
              {value}
            </span>
            <CopyButton
              value={value}
              onCopied={(ok) => {
                if (ok) void message.success('卡密已复制');
              }}
            />
          </Space>
        ),
      },
      {
        title: '导入时间',
        dataIndex: 'createdAt',
        key: 'createdAt',
        width: 170,
        sorter: true,
        sortOrder: sortOrderFor('createdAt'),
        render: (value: string) => formatDateTime(value),
      },
      {
        title: '封禁状态',
        dataIndex: 'banStatus',
        key: 'banStatus',
        width: 180,
        sorter: true,
        sortOrder: sortOrderFor('banStatus'),
        render: (value: BanStatus, record) => {
          const meta = BAN_STATUS_META[value] ?? BAN_STATUS_META.unknown;
          const tag = <Tag color={meta.color}>{meta.label}</Tag>;
          return (
            <div>
              {value === 'banned' && record.banReason ? (
                <Tooltip title={record.banReason}>{tag}</Tooltip>
              ) : (
                tag
              )}
              {value === 'banned' && record.banCheckedAt ? (
                <div className="table-sub">封禁时间：{formatDateTime(record.banCheckedAt)}</div>
              ) : null}
            </div>
          );
        },
      },
      {
        title: '兑换状态',
        dataIndex: 'redeemStatus',
        key: 'redeemStatus',
        width: 180,
        sorter: true,
        sortOrder: sortOrderFor('redeemStatus'),
        render: (value: RedeemStatus, record) => {
          const meta = REDEEM_STATUS_META[value] ?? REDEEM_STATUS_META.unredeemed;
          return (
            <div>
              <Tag color={meta.color}>{meta.label}</Tag>
              {value === 'redeemed' && record.redeemedAt ? (
                <div className="table-sub">兑换时间：{formatDateTime(record.redeemedAt)}</div>
              ) : null}
            </div>
          );
        },
      },
    ];

    const updated: ColumnsType<AccountRow> = extraColumns.includes('updatedAt')
      ? [
          {
            title: '更新时间',
            dataIndex: 'updatedAt',
            key: 'updatedAt',
            width: 170,
            sorter: true,
            sortOrder: sortOrderFor('updatedAt'),
            render: (value: string) => formatDateTime(value),
          },
        ]
      : [];

    const action: ColumnsType<AccountRow> = [
      {
        title: '操作',
        key: 'action',
        width: 200,
        fixed: 'right',
        render: (_, record) => (
          <Space size={0} wrap>
            <Button
              type="link"
              size="small"
              onClick={() => {
                void handleCopyCard(record);
              }}
            >
              复制卡密
            </Button>
            <Button
              type="link"
              size="small"
              disabled={!record.hasMailbox}
              onClick={() => setMailboxAccount(record)}
            >
              取件
            </Button>
            <Dropdown
              trigger={['click']}
              menu={{
                onClick: ({ key }) => {
                  if (key === 'remark') {
                    remarkForm.setFieldsValue({ remark: record.remark ?? '' });
                    setRemarkTarget(record);
                  }
                  if (key === 'email') void handleCopyEmail(record);
                },
                items: [
                  { key: 'remark', label: '编辑备注' },
                  { key: 'email', label: '复制邮箱' },
                ],
              }}
            >
              <Button type="link" size="small">
                更多
                <DownOutlined style={{ fontSize: 10 }} />
              </Button>
            </Dropdown>
            <Popconfirm
              title="加入待删除列表？"
              description="选中后在工具栏点击「批量删除」执行删除。"
              okText="加入"
              cancelText="取消"
              onConfirm={() => addToDeleteSelection(record.id)}
            >
              <Button type="link" size="small" danger>
                删除
              </Button>
            </Popconfirm>
          </Space>
        ),
      },
    ];

    return [...core, ...updated, ...action];
  }, [
    extraColumns,
    filters.sortField,
    filters.sortOrder,
    handleCopyCard,
    handleCopyEmail,
    addToDeleteSelection,
    message,
    remarkForm,
  ]);

  const handleTableChange: TableProps<AccountRow>['onChange'] = (pagination, _tableFilters, sorter) => {
    const single = Array.isArray(sorter) ? sorter[0] : sorter;
    const fieldKey = single?.field;
    const field = typeof fieldKey === 'string' ? (fieldKey as AccountSortField) : undefined;
    const order = single?.order ?? undefined;

    setPage(pagination.current ?? 1);
    setPageSize(pagination.pageSize ?? PAGE_SIZE_DEFAULT);
    setFilters((previous) => ({
      ...previous,
      sortField: order ? field : undefined,
      sortOrder: order ?? undefined,
    }));
  };

  const refreshFilterPayload: RefreshFilterPayload = {
    credits: filters.credits.length > 0 ? filters.credits : undefined,
    banStatus: filters.banStatus.length > 0 ? filters.banStatus : undefined,
    redeemStatus: filters.redeemStatus.length > 0 ? filters.redeemStatus : undefined,
    keyword: filters.keyword || undefined,
  };

  const summaryCells = [
    { key: 'total', label: '账号总数', value: summary.total },
    { key: 'pending', label: '待定档', value: summary.pending },
    { key: 'unredeemed', label: '未兑换', value: summary.unredeemed },
    { key: 'redeemed', label: '已兑换', value: summary.redeemed },
    { key: 'banned', label: '已封禁', value: summary.banned },
    { key: 'invalid', label: '凭据失效', value: summary.invalid },
  ];

  return (
    <>
      <div className="admin-toolbar">
        <Space wrap>
          <Select
            mode="multiple"
            allowClear
            placeholder="额度筛选"
            style={{ minWidth: 180 }}
            value={filters.credits}
            options={creditSelectOptions}
            onChange={(value: number[]) => {
              setFilters((previous) => ({ ...previous, credits: value }));
              setPage(1);
            }}
          />
          <Select
            mode="multiple"
            allowClear
            placeholder="封禁状态筛选"
            style={{ minWidth: 180 }}
            value={filters.banStatus}
            options={BAN_STATUS_OPTIONS}
            onChange={(value: BanStatus[]) => {
              setFilters((previous) => ({ ...previous, banStatus: value }));
              setPage(1);
            }}
          />
          <Select
            mode="multiple"
            allowClear
            placeholder="兑换状态筛选"
            style={{ minWidth: 180 }}
            value={filters.redeemStatus}
            options={REDEEM_STATUS_OPTIONS}
            onChange={(value: RedeemStatus[]) => {
              setFilters((previous) => ({ ...previous, redeemStatus: value }));
              setPage(1);
            }}
          />
          <Input.Search
            allowClear
            placeholder="账号名 / 卡密 / 邮箱"
            style={{ width: 220 }}
            onSearch={(value) => {
              setFilters((previous) => ({ ...previous, keyword: value.trim() }));
              setPage(1);
            }}
          />
          <Select
            allowClear
            placeholder="排序"
            style={{ minWidth: 140 }}
            value={sortValue}
            options={SORT_PRESETS.map((item) => ({ value: item.value, label: item.label }))}
            onChange={(value?: string) => {
              const preset = SORT_PRESETS.find((item) => item.value === value);
              setFilters((previous) => ({
                ...previous,
                sortField: preset?.field,
                sortOrder: preset?.order,
              }));
              setPage(1);
            }}
          />
          <Button onClick={resetFilters}>重置</Button>
          <Dropdown
            menu={{
              items: EXPORT_ITEMS,
              onClick: ({ key }) => {
                void handleExport(key as DeliverFormat);
              },
            }}
          >
            <Button icon={<DownloadOutlined />}>导出</Button>
          </Dropdown>
          <Dropdown
            menu={{
              items: copyKeyMenuItems,
              onClick: ({ key }) => {
                void handleCopyKeys(key as CardCopyScope);
              },
            }}
          >
            <Button icon={<CopyOutlined />} loading={copyingKeys}>
              批量复制卡密
              {selectedIds.length > 0 ? ` (${selectedIds.length})` : ''} <DownOutlined />
            </Button>
          </Dropdown>
        </Space>

        <Space wrap>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setImportOpen(true);
            }}
          >
            导入账号
          </Button>
          <Button
            icon={<SyncOutlined />}
            onClick={() => {
              setRefreshOpen(true);
            }}
          >
            刷新状态
          </Button>
          <Button
            disabled={selectedIds.length === 0}
            onClick={() => {
              setRetagOpen(true);
            }}
          >
            改标记
            {selectedIds.length > 0 ? ` (${selectedIds.length})` : ''}
          </Button>
          <Popconfirm
            title={`删除选中的 ${selectedIds.length} 个账号？`}
            description="删除后不可恢复。"
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            disabled={selectedIds.length === 0}
            onConfirm={() => {
              void handleBatchDelete();
            }}
          >
            <Button danger disabled={selectedIds.length === 0} loading={deleting}>
              批量删除
              {selectedIds.length > 0 ? ` (${selectedIds.length})` : ''}
            </Button>
          </Popconfirm>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => {
              void load();
            }}
          >
            刷新列表
          </Button>
          <Dropdown
            menu={{
              selectable: true,
              multiple: true,
              selectedKeys: extraColumns,
              items: [{ key: 'updatedAt', label: '更新时间' }],
              onClick: ({ key }) => {
                setExtraColumns((previous) =>
                  previous.includes(key) ? previous.filter((item) => item !== key) : [...previous, key],
                );
              },
            }}
          >
            <Button>列</Button>
          </Dropdown>
        </Space>
      </div>

      <div className="admin-summary-strip">
        {summaryCells.map((item) => (
          <div className="admin-summary-cell" key={item.key}>
            <div className="admin-summary-cell__label">{item.label}</div>
            <div className="admin-summary-cell__value">{formatNumber(item.value)}</div>
          </div>
        ))}
      </div>

      <div className="admin-card">
        <Table<AccountRow>
          rowKey="id"
          size="small"
          loading={loading}
          columns={columns}
          dataSource={rows}
          scroll={{ x: 1500 }}
          onChange={handleTableChange}
          rowSelection={{
            selectedRowKeys: selectedIds,
            onChange: (keys) => setSelectedIds(keys.map((key) => Number(key))),
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            pageSizeOptions: ['20', '50', '100', '200'],
            showTotal: (count) => `共 ${count} 条`,
          }}
          locale={{
            emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无账号数据" />,
          }}
        />
      </div>

      <ImportAccountsModal
        open={importOpen}
        tiers={tiers}
        onClose={() => setImportOpen(false)}
        onImported={() => {
          void load();
        }}
      />

      <RefreshStatusModal
        open={refreshOpen}
        selectedIds={selectedIds}
        filter={refreshFilterPayload}
        total={total}
        onClose={() => setRefreshOpen(false)}
        onDone={() => {
          void load();
        }}
      />

      <MailboxModal
        open={mailboxAccount !== null}
        account={mailboxAccount}
        onClose={() => setMailboxAccount(null)}
        onChanged={() => {
          void load();
        }}
      />

      <Modal
        title={`改标记 · ${selectedIds.length} 个账号`}
        open={retagOpen}
        confirmLoading={retagging}
        okText="保存"
        cancelText="取消"
        onOk={() => {
          void handleRetag();
        }}
        onCancel={() => setRetagOpen(false)}
        destroyOnClose
      >
        <Form form={retagForm} layout="vertical" preserve={false} style={{ marginTop: 12 }} initialValues={{ subscriptionTag: 'Plus' }}>
          <Form.Item name="subscriptionTag" label="订阅标记" rules={[{ required: true, message: '请选择订阅标记' }]}>
            <Select options={SUBSCRIPTION_TAG_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="customSubscriptionTag"
            label="自定义短标记"
            extra="填写后优先使用。5X Team 会按 token 核对空间，对不上的行不会改。"
            rules={[{ validator: async (_, value) => {
              const reason = subscriptionTagError(String(value || ''));
              if (reason) throw new Error(reason);
            } }]}
          >
            <Input maxLength={32} placeholder="例如 Pro5x" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`编辑备注 · ${remarkTarget?.name ?? ''}`}
        open={remarkTarget !== null}
        confirmLoading={remarkSaving}
        okText="保存"
        cancelText="取消"
        onOk={() => {
          void submitRemark();
        }}
        onCancel={() => setRemarkTarget(null)}
        destroyOnClose
      >
        <Form form={remarkForm} layout="vertical" preserve={false} style={{ marginTop: 12 }}>
          <Form.Item name="remark" label="备注">
            <TextArea rows={3} placeholder="内部备注，可留空" />
          </Form.Item>
          <div style={{ fontSize: 11.5, color: '#98A5A0' }}>
            当前额度 <b>{formatCredits(remarkTarget?.credits ?? 0)}</b>
            ：档位由邮箱取件命中额度关键字自动得出，不在这里手工修改。
          </div>
        </Form>
      </Modal>
    </>
  );
}
