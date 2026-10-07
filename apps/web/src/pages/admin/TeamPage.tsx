import { useCallback, useEffect, useState } from 'react';
import { App as AntApp, Button, Card, Form, Input, Modal, Space, Table, Tabs, Typography } from 'antd';

import {
  ApiError,
  assignTeam,
  createTeamWorkspace,
  errorMessage,
  getTeamStatus,
  importTeamLines,
  kickAllTeam,
  kickSelectedTeam,
  previewKickAllTeam,
  kickTeamMember,
  listRemoteMembers,
  listTeamJobs,
  listTeamMembers,
  listTeamWaiting,
  listTeamWorkspaces,
  patchChildProxy,
  previewTeamSession,
  probeTeam,
  refreshTeam,
  revealChildSecret,
  revealTeamSession,
  revokeTeamInvites,
  updateTeamWorkspace,
  type RemoteMemberRow,
  type TeamMemberRow,
  type TeamWorkspaceRow,
} from '../../api/client';

const { TextArea } = Input;
const { Paragraph, Text } = Typography;

function rateLimitText(job: unknown): string {
  const text = job && typeof job === 'object' && 'message' in job ? String((job as { message?: string }).message || '') : '';
  return text.includes('可能被限流') ? text : '';
}

function detachedNames(saved: unknown): string[] {
  if (!saved || typeof saved !== 'object' || !('detachedChildren' in saved)) return [];
  const names = (saved as { detachedChildren?: unknown }).detachedChildren;
  return Array.isArray(names) ? names.map((item) => String(item || '')).filter(Boolean) : [];
}

function expiryText(value?: string | null, willRenew?: boolean | null) {
  const text = String(value || '').trim();
  if (!text) return '未知';
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(text);
  let shown = text;
  if (hasZone) {
    const date = new Date(text);
    if (Number.isNaN(date.getTime())) return '未知';
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    }).formatToParts(date);
    const pick = (type: string) => parts.find((item) => item.type === type)?.value || '';
    shown = `${pick('year')}-${pick('month')}-${pick('day')} ${pick('hour')}:${pick('minute')}:${pick('second')}`;
  } else {
    shown = `${text}（时区不明）`;
  }
  return willRenew === false ? `${shown} 不续费` : shown;
}

function jobMessage(result: unknown): string {
  if (!result || typeof result !== 'object' || !('message' in result)) return '';
  return String((result as { message?: string }).message || '');
}

function resetText(value?: number | null) {
  if (value == null) return '—';
  const ms = value > 10_000_000_000 ? value : value * 1000;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function keptSession(error: unknown): string {
  if (!(error instanceof ApiError) || !error.details || typeof error.details !== 'object') return '';
  const session = (error.details as { session?: unknown }).session;
  return typeof session === 'string' && session.trim() ? session : '';
}

function workspaceChoices(error: unknown): Array<{ id: string; name: string }> {
  if (!(error instanceof ApiError) || !error.details || typeof error.details !== 'object') return [];
  const raw = (error.details as { workspaces?: unknown }).workspaces;
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((item) => {
    if (!item || typeof item !== 'object') return [];
    const row = item as { id?: unknown; name?: unknown };
    const id = typeof row.id === 'string' ? row.id : '';
    if (!id) return [];
    return [{ id, name: typeof row.name === 'string' && row.name ? row.name : id }];
  });
}

function motherLabel(workspaces: TeamWorkspaceRow[], workspaceId: number | null) {
  const mother = workspaces.find((item) => item.id === workspaceId);
  if (!mother) return '未归入母号';
  return `${mother.email || '母号'} / ${mother.displayName || mother.workspaceId || '空间'}`;
}

export default function TeamPage() {
  const { message, modal } = AntApp.useApp();
  const [notice, setNotice] = useState('');
  const [workspaces, setWorkspaces] = useState<TeamWorkspaceRow[]>([]);
  const [members, setMembers] = useState<TeamMemberRow[]>([]);
  const [remoteMembers, setRemoteMembers] = useState<RemoteMemberRow[]>([]);
  const [picked, setPicked] = useState<Record<number, string[]>>({});
  const [waiting, setWaiting] = useState<Array<{ id: number; cardKey: string | null; email: string | null; teamStatus: string | null }>>([]);
  const [jobs, setJobs] = useState<Array<{ id: number; workspaceRowId: number; kind: string; status: string; message: string; createdAt: string }>>([]);
  const [sessionOpen, setSessionOpen] = useState(false);
  const [sessionText, setSessionText] = useState('');
  const [proxyText, setProxyText] = useState('');
  const [workspaceText, setWorkspaceText] = useState('');
  const [choices, setChoices] = useState<Array<{ id: string; name: string }>>([]);
  const [sessionView, setSessionView] = useState<{ id: number; preview: string; full: string; warn: boolean } | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [importText, setImportText] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [status, mothers, people, remote, queue, history] = await Promise.all([
      getTeamStatus(),
      listTeamWorkspaces(),
      listTeamMembers(),
      listRemoteMembers(),
      listTeamWaiting(),
      listTeamJobs(),
    ]);
    const missing = [
      status.secretReady ? '' : 'GPTCDK_SECRET 未配置，Team 已停用',
      status.workerReady ? '' : '协议服务未配置，Team 操作已停用',
    ].filter(Boolean);
    setNotice(missing.join('；'));
    setWorkspaces(mothers.items || []);
    setMembers(people.items || []);
    setRemoteMembers(remote.items || []);
    setWaiting(queue.items || []);
    setJobs(history.items || []);
  }, []);

  useEffect(() => {
    void load().catch((error) => message.error(errorMessage(error)));
  }, [load, message]);

  const run = async (work: () => Promise<unknown>, done: string) => {
    setBusy(true);
    try {
      const result = await work();
      void message.success(jobMessage(result) || done);
      await load();
    } catch (error) {
      void message.error(errorMessage(error));
      await load().catch(() => undefined);
    } finally {
      setBusy(false);
    }
  };

  const memberColumns = [
    { title: '邮箱', dataIndex: 'email', render: (value: string | null) => value || '已踢出' },
    { title: '卡密', dataIndex: 'cardKey' },
    { title: '状态', dataIndex: 'teamStatus' },
    { title: '额度', render: (_: unknown, row: TeamMemberRow) => row.usage?.label || '未探测' },
    { title: '5 小时', render: (_: unknown, row: TeamMemberRow) => row.usage?.pct5h == null ? '未探测' : `${row.usage.pct5h}%` },
    { title: '7 天', render: (_: unknown, row: TeamMemberRow) => row.usage?.pct7d == null ? '未探测' : `${row.usage.pct7d}%` },
    { title: '5 小时重置', render: (_: unknown, row: TeamMemberRow) => resetText(row.usage?.reset5h) },
    { title: '7 天重置', render: (_: unknown, row: TeamMemberRow) => resetText(row.usage?.reset7d) },
    {
      title: '操作',
      render: (_: unknown, row: TeamMemberRow) => {
        const mother = workspaces.find((item) => item.id === row.workspaceId)
          || workspaces.find((item) => row.priorRemoteWorkspaceId && item.workspaceId === row.priorRemoteWorkspaceId);
        const canKick = Boolean(row.userId || row.priorUserId) && mother?.snapshotComplete === true;
        return (
          <Space>
            <Button size="small" onClick={() => void revealChildSecret(row.id).then((secret) => {
              modal.info({ title: '子号账密', content: <Paragraph copyable>{`${secret.email}----${secret.password}----${secret.totp}`}</Paragraph> });
            }).catch((error) => message.error(errorMessage(error)))}>查看账密</Button>
            <Button size="small" onClick={() => {
              void revealChildSecret(row.id).then((secret) => {
                let proxy = secret.socks || '';
                modal.confirm({
                  title: '子号 SOCKS',
                  content: <Input defaultValue={proxy} onChange={(event) => { proxy = event.target.value; }} placeholder="socks5://主机:端口" />,
                  onOk: () => patchChildProxy(row.id, proxy).then(load).catch((error) => message.error(errorMessage(error))),
                });
              }).catch((error) => message.error(errorMessage(error)));
            }}>设置代理</Button>
            <Button size="small" disabled={!canKick} onClick={() => modal.confirm({
              title: row.redeemStatus === 'redeemed' ? '这张卡密已经兑换过，踢出后账密和文件不能恢复' : '确认踢出这个子号？',
              content: `邮箱 ${row.email || '无'}，卡密 ${row.cardKey || '无'}，${row.redeemStatus === 'redeemed' ? '已兑换' : '未兑换'}。只退出这个子号。`,
              onOk: () => kickTeamMember(row.id).then((job) => {
                const warning = rateLimitText(job);
                if (warning) void message.warning(warning);
                return load();
              }).catch((error) => message.error(errorMessage(error))),
            })}>踢出</Button>
          </Space>
        );
      },
    },
  ];
  const memberGroups = new Map<string, TeamMemberRow[]>();
  for (const row of members) {
    const key = String(row.workspaceId ?? 'none');
    const list = memberGroups.get(key) || [];
    list.push(row);
    memberGroups.set(key, list);
  }

  const openMother = (id: number | null, workspaceId = '') => {
    setEditingId(id);
    setSessionText('');
    setProxyText('');
    setWorkspaceText(workspaceId);
    setChoices([]);
    setSessionOpen(true);
  };

  const saveMother = async () => {
    const body = {
      session: sessionText,
      ...(proxyText.trim() ? { socks: proxyText.trim() } : {}),
      ...(sessionText.trim() && workspaceText.trim() ? { workspaceId: workspaceText.trim() } : {}),
    };
    setBusy(true);
    try {
      const saved = editingId ? await updateTeamWorkspace(editingId, body) : await createTeamWorkspace(body);
      const detached = detachedNames(saved);
      setSessionOpen(false);
      setSessionText('');
      setProxyText('');
      setWorkspaceText('');
      setChoices([]);
      setEditingId(null);
      if (detached.length) void message.warning(`已改绑空间，这些子号已从这一行拆开：${detached.join('、')}`);
      void message.success('母号已保存');
      await load();
    } catch (error) {
      const kept = keptSession(error);
      if (kept) setSessionText(kept);
      const next = workspaceChoices(error);
      if (next.length) {
        setChoices(next);
        void message.warning(kept ? '这次检查换过 session，已放回输入框。请点选空间后再保存' : '这份 session 有多个 Team 空间，请点选一个');
        return;
      }
      if (kept) void message.warning('这次检查换过 session，已放回输入框。请再保存一次，不要重新登录');
      void message.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      {notice ? <Card size="small"><Text type="warning">{notice}</Text></Card> : null}
      <Tabs
        items={[
          {
            key: 'mothers',
            label: '母号',
            children: (
              <Card
                size="small"
                extra={<Button type="primary" onClick={() => openMother(null)}>添加母号</Button>}
              >
                <Table
                  rowKey="id"
                  dataSource={workspaces}
                  pagination={false}
                  columns={[
                    { title: '邮箱', dataIndex: 'email' },
                    { title: '空间', dataIndex: 'displayName' },
                    { title: '空位', dataIndex: 'emptySeats', render: (value) => value ?? '未知' },
                    { title: '状态', render: (_, row) => {
                      const hold = row.inviteHold === 'seat_full' ? '席位已满已停止' : row.inviteHold === 'stopped' ? '空间不可用已停止' : row.sessionStatus;
                      return row.canAutoRenew === false ? `${hold}（不能自动续期）` : hold;
                    } },
                    { title: '到期', render: (_, row) => expiryText(row.activeUntil, row.willRenew) },
                    { title: '最近成功', dataIndex: 'lastSuccessAt', render: (value) => value || '—' },
                    { title: '最近错误', dataIndex: 'lastError', render: (value) => value || '—' },
                    {
                      title: '操作',
                      render: (_, row) => (
                        <Space wrap>
                          <Button size="small" onClick={() => void previewTeamSession(row.id).then((data) => {
                            setSessionView({ id: row.id, preview: data.preview, full: '', warn: data.canAutoRenew === false });
                          }).catch((error) => message.error(errorMessage(error)))}>查看</Button>
                          <Button size="small" onClick={() => openMother(row.id, row.workspaceId || '')}>更换</Button>
                          <Button size="small" loading={busy} onClick={() => void run(() => assignTeam(row.id), '分配已执行')}>分配</Button>
                          <Button size="small" loading={busy} onClick={() => void run(() => refreshTeam(row.id), '空间已刷新')}>刷新空间</Button>
                          <Button size="small" loading={busy} onClick={() => void run(() => probeTeam(row.id), '探测已完成')}>探测</Button>
                          <Button size="small" loading={busy} onClick={() => void run(() => revokeTeamInvites(row.id), '撤回已执行')}>撤回邀请</Button>
                          <Button size="small" danger disabled={!row.snapshotComplete} title={row.snapshotComplete ? undefined : '成员快照不完整'} onClick={() => {
                            void (async () => {
                              try {
                                const preview = await previewKickAllTeam(row.id);
                                if (!preview.userIds.length) {
                                  message.warning('当前没有可退出的普通成员');
                                  return;
                                }
                                const lines = preview.members.map((item) => `${item.email || '无邮箱'} / ${item.cardKey || '无卡密'} / ${item.redeemStatus === 'redeemed' ? '已兑换' : '未兑换'} / ${item.id}`);
                                let typed = '';
                                modal.confirm({
                                  title: '退出全部会清掉这个空间里的子号账密和文件',
                                  content: (
                                    <div>
                                      <Paragraph style={{ whiteSpace: 'pre-wrap' }}>{lines.join('\n')}</Paragraph>
                                      <Paragraph>只退出上面这些普通成员。母号和其他空间不会退出。踢出后账密和文件不能恢复。</Paragraph>
                                      <Input placeholder="请输入退出全部" onChange={(event) => { typed = event.target.value; }} />
                                    </div>
                                  ),
                                  okText: '退出全部',
                                  onOk: () => {
                                    if (typed.trim() !== '退出全部') {
                                      message.error('请输入「退出全部」');
                                      return Promise.reject(new Error('confirm'));
                                    }
                                    return kickAllTeam(row.id, preview.userIds).then((job) => {
                                      const warning = rateLimitText(job);
                                      if (warning) void message.warning(warning);
                                      return load();
                                    }).catch((error) => message.error(errorMessage(error)));
                                  },
                                });
                              } catch (error) {
                                message.error(errorMessage(error));
                              }
                            })();
                          }}>退出全部</Button>
                        </Space>
                      ),
                    },
                  ]}
                />
              </Card>
            ),
          },
          {
            key: 'members',
            label: '成员与额度',
            children: memberGroups.size === 0 ? (
              <Table rowKey="id" dataSource={[]} pagination={false} columns={memberColumns} />
            ) : (
              <Space direction="vertical" style={{ width: '100%' }}>
                {[...memberGroups.entries()].map(([key, rows]) => (
                  <Card key={key} size="small" title={motherLabel(workspaces, rows[0]?.workspaceId ?? null)}>
                    <Table rowKey="id" dataSource={rows} pagination={false} columns={memberColumns} />
                  </Card>
                ))}
              </Space>
            ),
          },
          {
            key: 'roster',
            label: '空间成员',
            children: remoteMembers.length === 0 ? (
              <Card size="small">还没有空间成员。先在母号上点「刷新空间」。</Card>
            ) : (
              <Space direction="vertical" style={{ width: '100%' }}>
                {[...new Set(remoteMembers.map((item) => item.workspaceRowId))].map((workspaceId) => {
                  const rows = remoteMembers.filter((item) => item.workspaceRowId === workspaceId);
                  const mother = rows[0];
                  const selected = picked[workspaceId] || [];
                  return (
                    <Card
                      key={workspaceId}
                      size="small"
                      title={`${mother?.workspaceName || '空间'} / ${mother?.motherEmail || ''}`}
                      extra={
                        <Button
                          size="small"
                          danger
                          disabled={!mother?.snapshotComplete || selected.length === 0}
                          title={mother?.snapshotComplete ? undefined : '成员快照不完整'}
                          onClick={() => {
                            let typed = '';
                            modal.confirm({
                              title: '踢出选中的普通成员',
                              content: (
                                <div>
                                  <Paragraph>只踢勾选的普通成员，不会自动分配空位。所有者不会被踢。</Paragraph>
                                  <Input placeholder="请输入踢出选中" onChange={(event) => { typed = event.target.value; }} />
                                </div>
                              ),
                              okText: '踢出选中',
                              onOk: () => {
                                if (typed.trim() !== '踢出选中') {
                                  message.error('请输入「踢出选中」');
                                  return Promise.reject(new Error('confirm'));
                                }
                                return kickSelectedTeam(workspaceId, selected).then((job) => {
                                  const warning = rateLimitText(job);
                                  if (warning) void message.warning(warning);
                                  else if (jobMessage(job)) void message.success(jobMessage(job));
                                  setPicked((current) => ({ ...current, [workspaceId]: [] }));
                                  return load();
                                }).catch((error) => {
                                  void message.error(errorMessage(error));
                                  return load();
                                });
                              },
                            });
                          }}
                        >踢出选中</Button>
                      }
                    >
                      {!mother?.snapshotComplete ? <Paragraph type="warning">名单不完整，下面仍是上次完整刷新的成员，现在不能踢人。</Paragraph> : null}
                      <Table
                        rowKey="key"
                        dataSource={rows}
                        pagination={false}
                        rowSelection={{
                          selectedRowKeys: rows.filter((row) => selected.includes(row.id)).map((row) => row.key),
                          getCheckboxProps: (row) => ({ disabled: row.role !== 'standard-user' || !mother?.snapshotComplete }),
                          onChange: (keys) => {
                            const ids = rows.filter((row) => keys.map(String).includes(row.key)).map((row) => row.id);
                            setPicked((current) => ({ ...current, [workspaceId]: ids }));
                          },
                        }}
                        columns={[
                          { title: '邮箱', dataIndex: 'email', render: (value: string) => value || '—' },
                          { title: '角色', dataIndex: 'role', render: (value: string) => value || '—' },
                          { title: '成员编号', dataIndex: 'id' },
                          { title: '卡密', dataIndex: 'cardKey', render: (value: string) => value || '—' },
                        ]}
                      />
                    </Card>
                  );
                })}
              </Space>
            ),
          },
          {
            key: 'waiting',
            label: '待分配',
            children: (
              <Space direction="vertical" style={{ width: '100%' }}>
                <Card size="small" title="导入免费子号">
                  <TextArea rows={6} value={importText} onChange={(event) => setImportText(event.target.value)} placeholder="邮箱----ChatGPT密码----2FA密钥" />
                  <Button style={{ marginTop: 12 }} type="primary" loading={busy} onClick={() => void run(async () => {
                    const result = await importTeamLines(importText);
                    setImportText('');
                    if (result.errors.length) message.warning(result.errors.join('；'));
                    if (result.assignError) message.warning(result.assignError);
                    if (result.created.length) message.info(result.created.map((item) => `${item.email} ${item.cardKey}`).join('\n'));
                  }, '已处理导入')}>导入并生成卡密</Button>
                </Card>
                <Table rowKey="id" dataSource={waiting} pagination={false} columns={[
                  { title: '邮箱', dataIndex: 'email' },
                  { title: '卡密', dataIndex: 'cardKey' },
                  { title: '状态', dataIndex: 'teamStatus' },
                  { title: '代理', render: (_, row) => <Button size="small" onClick={() => {
                    let proxy = '';
                    modal.confirm({
                      title: '子号 SOCKS',
                      content: <Input onChange={(event) => { proxy = event.target.value; }} placeholder="socks5://主机:端口" />,
                      onOk: () => patchChildProxy(row.id, proxy).then(load),
                    });
                  }}>设置代理</Button> },
                ]} />
              </Space>
            ),
          },
          {
            key: 'jobs',
            label: '任务',
            children: (
              <Table rowKey="id" dataSource={jobs} pagination={false} columns={[
                { title: '母号', dataIndex: 'workspaceRowId' },
                { title: '类型', dataIndex: 'kind' },
                { title: '状态', dataIndex: 'status' },
                { title: '结果', dataIndex: 'message', render: (value: string) => <div style={{ whiteSpace: 'pre-wrap' }}>{value || '—'}</div> },
                { title: '时间', dataIndex: 'createdAt' },
              ]} />
            ),
          },
        ]}
      />
      <Modal
        title={editingId ? '更换母号 session' : '添加母号'}
        open={sessionOpen}
        onCancel={() => setSessionOpen(false)}
        onOk={() => void saveMother()}
        confirmLoading={busy}
      >
        <Form layout="vertical">
          <Form.Item label="session JSON" extra="只在点保存时提交。列表里不会显示全文。">
            <TextArea rows={8} value={sessionText} onChange={(event) => setSessionText(event.target.value)} />
          </Form.Item>
          <Form.Item label="空间编号" extra="只有一份 Team 空间时可以留空。多个空间时点下面的按钮，或自己填写。">
            <Input value={workspaceText} onChange={(event) => setWorkspaceText(event.target.value)} />
          </Form.Item>
          {choices.length ? (
            <Form.Item label="点选空间">
              <Space wrap>
                {choices.map((item) => (
                  <Button key={item.id} type={workspaceText === item.id ? 'primary' : 'default'} onClick={() => setWorkspaceText(item.id)}>
                    {item.name}（{item.id}）
                  </Button>
                ))}
              </Space>
            </Form.Item>
          ) : null}
          <Form.Item label="母号 SOCKS，可留空" extra="留空不会改掉原来的代理，也不会直连。">
            <Input value={proxyText} onChange={(event) => setProxyText(event.target.value)} placeholder="socks5://主机:端口" />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title="母号 session"
        open={Boolean(sessionView)}
        onCancel={() => setSessionView(null)}
        footer={[
          <Button key="close" onClick={() => setSessionView(null)}>关闭</Button>,
          <Button key="full" type="primary" disabled={!sessionView || Boolean(sessionView.full)} onClick={() => {
            if (!sessionView) return;
            void revealTeamSession(sessionView.id).then((data) => {
              setSessionView({ ...sessionView, full: data.session });
            }).catch((error) => message.error(errorMessage(error)));
          }}>查看全部</Button>,
        ]}
      >
        {sessionView?.warn ? <Paragraph type="warning">这份 session 没有可回放的网页 cookie，不能自动续期。</Paragraph> : null}
        <Paragraph copyable={sessionView?.full ? { text: sessionView.full } : false} style={{ whiteSpace: 'pre-wrap' }}>
          {sessionView?.full || sessionView?.preview || '—'}
        </Paragraph>
      </Modal>
    </Space>
  );
}
