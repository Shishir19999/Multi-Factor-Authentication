import { useId, useState } from 'react';

// Labelled input with hint and inline error wired up through aria-describedby / aria-invalid.
function Field({ label, error, hint, type = 'text', className = '', children, ...rest }) {
  const id = useId();
  const describedBy = [error && `${id}-err`, hint && `${id}-hint`].filter(Boolean).join(' ') || undefined;
  const input = (
    <input
      id={id}
      type={type}
      className="input"
      aria-invalid={error ? true : undefined}
      aria-describedby={describedBy}
      {...rest}
    />
  );
  return (
    <div className={`field${error ? ' has-error' : ''}${className ? ` ${className}` : ''}`}>
      <label htmlFor={id}>{label}</label>
      {children ? <div className="input-wrap">{input}{children}</div> : input}
      {hint && !error && <p className="hint" id={`${id}-hint`}>{hint}</p>}
      {error && <p className="error-text" id={`${id}-err`}>{error}</p>}
    </div>
  );
}

// Password input with a show/hide toggle.
export function PasswordField({ label = 'Password', autoComplete = 'current-password', ...rest }) {
  const [shown, setShown] = useState(false);
  return (
    <Field label={label} type={shown ? 'text' : 'password'} autoComplete={autoComplete} {...rest}>
      <button
        type="button"
        className="reveal-btn"
        onClick={() => setShown((s) => !s)}
        aria-pressed={shown}
        aria-label={shown ? 'Hide password' : 'Show password'}
      >
        {shown ? 'Hide' : 'Show'}
      </button>
    </Field>
  );
}

export default Field;
