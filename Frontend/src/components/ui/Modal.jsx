import { useEffect, useId, useRef } from 'react';

// Accessible modal built on the native <dialog>: focus is trapped, Escape closes, focus returns to the opener.
function Modal({ open, title, onClose, children, footer, wide = false }) {
  const ref = useRef(null);
  const titleId = useId();

  useEffect(() => {
    const dlg = ref.current;
    if (!dlg) return undefined;
    if (open && !dlg.open) dlg.showModal();
    if (!open && dlg.open) dlg.close();
    return undefined;
  }, [open]);

  if (!open) return null;

  return (
    <dialog
      ref={ref}
      className={`modal${wide ? ' modal-wide' : ''}`}
      aria-labelledby={titleId}
      onCancel={(e) => { e.preventDefault(); onClose(); }}
      onClick={(e) => { if (e.target === ref.current) onClose(); }}
    >
      <div className="modal-body">
        <div className="modal-head">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close dialog">×</button>
        </div>
        <div className="modal-content">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </dialog>
  );
}

export default Modal;
