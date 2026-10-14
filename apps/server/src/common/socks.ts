export function normalizeSocks(value: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error('没有可用的 SOCKS 代理');
  if (/^https?:\/\//i.test(text)) throw new Error('只接受 SOCKS 代理');
  if (text.startsWith('socks5://') || text.startsWith('socks5h://')) return text;
  const parts = text.split(':');
  if (parts.length === 4 && /^\d+$/.test(parts[1]) && parts[0] && parts[2] && parts[3]) {
    return `socks5://${encodeURIComponent(parts[2])}:${encodeURIComponent(parts[3])}@${parts[0]}:${parts[1]}`;
  }
  if (parts.length === 2 && /^\d+$/.test(parts[1]) && parts[0]) return `socks5://${parts[0]}:${parts[1]}`;
  throw new Error('SOCKS 代理格式应为 socks5:// 或 host:port:user:pass');
}
