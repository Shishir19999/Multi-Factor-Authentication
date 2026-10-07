import { useCallback, useMemo, useRef, useState } from 'react';
import { ToastContext } from './contexts';

const ICONS = { success: '✓', error: '!', info: 'i' };

// Toasts announce themselves to screen readers (alert for errors, status otherwise) and dismiss on their own.
function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id) => setItems((list) => list.filter((t) => t.id !== id)), []);

  const toast = useCallback((message, type = 'info') => {
    const id = nextId.current++;
    setItems((list) => [...list.slice(-3), { id, message, type }]);
    setTimeout(() => dismiss(id), type === 'error' ? 7000 : 4500);
  }, [dismiss]);

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toasts" role="region" aria-label="Notifications">
        {items.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`} role={t.type === 'error' ? 'alert' : 'status'}>
            <span className="toast-icon" aria-hidden="true">{ICONS[t.type]}</span>
            <span className="toast-text">{t.message}</span>
            <button type="button" className="toast-close" onClick={() => dismiss(t.id)} aria-label="Dismiss notification">×</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export default ToastProvider;
