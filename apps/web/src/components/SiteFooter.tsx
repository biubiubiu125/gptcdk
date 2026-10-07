import { Link } from 'react-router-dom';

export interface SiteFooterProps {
  /** 站点名，默认 gptcdk */
  siteName?: string;
}

/**
 * 公共站点页脚。
 */
export default function SiteFooter({ siteName = 'gptcdk' }: SiteFooterProps) {
  const year = new Date().getFullYear();

  return (
    <footer className="site-footer">
      <div className="shell site-footer__inner">
        <span>
          © {year} {siteName} · 卡密交付中心
        </span>
        <nav className="site-footer__links">
          <Link to="/">卡密兑换</Link>
          <Link to="/reclaim">401 找回</Link>
          <Link to="/pickup">邮箱取件</Link>
        </nav>
      </div>
    </footer>
  );
}
