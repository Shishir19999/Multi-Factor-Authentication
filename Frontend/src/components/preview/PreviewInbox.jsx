import { useEffect, useId, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { clearMail, listMail, subscribeMail } from '../../api/previewStore';
import { useToast } from '../../context/contexts';
import { timeAgo } from '../../lib/format';

export const OPEN_INBOX_EVENT = 'mfa:open-inbox';
// Only the sign-in and recovery screens have room for the panel to open by itself; elsewhere it would cover the page.
const AUTO_OPEN = ['/login', '/recover'];

// Stands in for the user's mailbox in the Live preview: the codes and links the real server would e-mail land here.
function PreviewInbox() {
  const [mails, setMails] = useState(listMail);
  const { pathname, key } = useLocation();
  const [openAt, setOpenAt] = useState(null); // the panel belongs to the route it was opened on, so it closes on navigation
  const open = openAt === key; // each navigation has its own key, so the panel never reopens on a later visit
  const pathRef = useRef({ pathname, key });
  const [unread, setUnread] = useState(0);
  const seen = useRef(listMail().length ? listMail()[0].id : null);
  const panelId = useId();
  const { toast } = useToast();

  useEffect(() => { pathRef.current = { pathname, key }; }, [pathname, key]);

  useEffect(() => subscribeMail(() => {
    const next = listMail();
    setMails(next);
    if (next[0] && next[0].id !== seen.current) {
      seen.current = next[0].id;
      setUnread((n) => n + 1);
      // Wide screens have room beside the form; on phones the panel would cover it, so only the badge shows.
      if (window.matchMedia?.('(min-width: 900px)').matches && AUTO_OPEN.includes(pathRef.current.pathname)) setOpenAt(pathRef.current.key);
      else toast('New message in the Preview inbox.', 'info');
    }
  }), [toast]);

  useEffect(() => {
    const openIt = () => setOpenAt(pathRef.current.key);
    window.addEventListener(OPEN_INBOX_EVENT, openIt);
    return () => window.removeEventListener(OPEN_INBOX_EVENT, openIt);
  }, []);

  const toggle = () => { setOpenAt(open ? null : key); setUnread(0); };

  const copy = async (code) => {
    try {
      await navigator.clipboard.writeText(code);
      toast('Code copied.', 'success');
    } catch {
      toast('Select the code and copy it manually.', 'info');
    }
  };

  return (
    <div className="preview-inbox">
      {open && (
        <section id={panelId} className="inbox-panel" aria-label="Preview inbox" aria-live="polite">
          <div className="inbox-head">
            <h2>Preview inbox</h2>
            <button type="button" className="icon-btn" onClick={() => { setOpenAt(null); setUnread(0); }} aria-label="Close Preview inbox">×</button>
          </div>
          <p className="inbox-note">Live preview only: normally these messages arrive by e-mail. Nothing is actually sent.</p>
          {mails.length === 0 ? (
            <p className="inbox-empty">No messages yet. Sign in with a sample account that uses e-mail codes and the code will show up here.</p>
          ) : (
            <ul className="inbox-list">
              {mails.map((m) => (
                <li key={m.id} className="inbox-item">
                  <div className="inbox-meta"><strong>{m.subject}</strong><span>{timeAgo(m.at)}</span></div>
                  <div className="inbox-to">To: {m.to}</div>
                  <p>{m.text}</p>
                  {m.code && (
                    <div className="inbox-code-row">
                      <code className="inbox-code" aria-label={`Code ${m.code.split('').join(' ')}`}>{m.code}</code>
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => copy(m.code)}>Copy<span className="sr-only"> code</span></button>
                    </div>
                  )}
                  {m.link && <a className="btn btn-secondary btn-sm" href={m.link} onClick={() => setOpenAt(null)}>Review this sign-in</a>}
                </li>
              ))}
            </ul>
          )}
          {mails.length > 0 && <button type="button" className="link-btn" onClick={clearMail}>Clear inbox</button>}
        </section>
      )}
      <button type="button" className="inbox-fab" onClick={toggle} aria-expanded={open} aria-controls={open ? panelId : undefined}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="3" y="5" width="18" height="14" rx="2" /><path d="m3 7 9 6 9-6" />
        </svg>
        Preview inbox
        {unread > 0 && <span className="badge" aria-label={`${unread} new message${unread === 1 ? '' : 's'}`}>{unread}</span>}
      </button>
    </div>
  );
}

export default PreviewInbox;
