import { useEffect, useId, useRef, useState } from 'react';
import { clearMail, listMail, subscribeMail } from '../../api/demoStore';
import { useToast } from '../../context/contexts';
import { timeAgo } from '../../lib/format';

export const OPEN_INBOX_EVENT = 'mfa:open-inbox';

// Stands in for the user's mailbox in the browser-only demo: the one-time codes "sent by e-mail" land here.
function DemoInbox() {
  const [mails, setMails] = useState(listMail);
  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const seen = useRef(listMail().length ? listMail()[0].id : null);
  const panelId = useId();
  const { toast } = useToast();

  useEffect(() => subscribeMail(() => {
    const next = listMail();
    setMails(next);
    if (next[0] && next[0].id !== seen.current) {
      seen.current = next[0].id;
      setUnread((n) => n + 1);
      // Wide screens have room beside the form; on phones the panel would cover it, so only the badge shows.
      if (window.matchMedia?.('(min-width: 900px)').matches) setOpen(true);
    }
  }), []);

  useEffect(() => {
    const openIt = () => setOpen(true);
    window.addEventListener(OPEN_INBOX_EVENT, openIt);
    return () => window.removeEventListener(OPEN_INBOX_EVENT, openIt);
  }, []);

  const toggle = () => { setOpen((o) => !o); setUnread(0); };

  const copy = async (code) => {
    try {
      await navigator.clipboard.writeText(code);
      toast('Code copied.', 'success');
    } catch {
      toast('Select the code and copy it manually.', 'info');
    }
  };

  return (
    <div className="demo-inbox">
      {open && (
        <section id={panelId} className="inbox-panel" aria-label="Demo inbox" aria-live="polite">
          <div className="inbox-head">
            <h2>Demo inbox</h2>
            <button type="button" className="icon-btn" onClick={() => { setOpen(false); setUnread(0); }} aria-label="Close demo inbox">×</button>
          </div>
          <p className="inbox-note">Demo only: normally these codes arrive by e-mail. Nothing is actually sent.</p>
          {mails.length === 0 ? (
            <p className="inbox-empty">No messages yet. Sign in with a demo account that uses e-mail codes and the code will show up here.</p>
          ) : (
            <ul className="inbox-list">
              {mails.map((m) => (
                <li key={m.id} className="inbox-item">
                  <div className="inbox-meta"><strong>{m.subject}</strong><span>{timeAgo(m.at)}</span></div>
                  <div className="inbox-to">To: {m.to}</div>
                  <p>{m.text}</p>
                  <div className="inbox-code-row">
                    <code className="inbox-code" aria-label={`Code ${m.code.split('').join(' ')}`}>{m.code}</code>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => copy(m.code)}>Copy</button>
                  </div>
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
        Demo inbox
        {unread > 0 && <span className="badge" aria-label={`${unread} new message${unread === 1 ? '' : 's'}`}>{unread}</span>}
      </button>
    </div>
  );
}

export default DemoInbox;
