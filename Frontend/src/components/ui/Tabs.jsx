import { useRef } from 'react';

// Accessible tab list (roving tabindex, arrow/Home/End keys). The caller renders the matching tabpanel with
// id `${id}-panel-${active}` and aria-labelledby `${id}-tab-${active}`.
function Tabs({ id, label, tabs, active, onChange }) {
  const refs = useRef({});
  const onKeyDown = (e) => {
    const i = tabs.findIndex((t) => t.id === active);
    let next = null;
    if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
    if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
    if (e.key === 'Home') next = tabs[0];
    if (e.key === 'End') next = tabs[tabs.length - 1];
    if (next) { e.preventDefault(); onChange(next.id); refs.current[next.id]?.focus(); }
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {tabs.map((t) => (
        <button
          key={t.id}
          ref={(el) => { refs.current[t.id] = el; }}
          id={`${id}-tab-${t.id}`}
          role="tab"
          type="button"
          className="tab"
          aria-selected={active === t.id}
          aria-controls={`${id}-panel-${t.id}`}
          tabIndex={active === t.id ? 0 : -1}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.badge > 0 && <span className="badge" aria-label={`${t.badge} need attention`}>{t.badge}</span>}
        </button>
      ))}
    </div>
  );
}

export default Tabs;
