import Button from './Button';

export function Skeleton({ lines = 3, height = 16, className = '' }) {
  return (
    <div className={`skeleton-group ${className}`} aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className="skeleton" style={{ height, width: i === lines - 1 ? '60%' : '100%' }} />
      ))}
    </div>
  );
}

// Wraps loading placeholders so assistive tech hears "Loading" once.
export function Loading({ label = 'Loading', lines = 4 }) {
  return (
    <div role="status" aria-live="polite">
      <span className="sr-only">{label}…</span>
      <Skeleton lines={lines} height={18} />
    </div>
  );
}

export function EmptyState({ title, children, action }) {
  return (
    <div className="state state-empty">
      <div className="state-icon" aria-hidden="true">∅</div>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ message = 'Something went wrong.', onRetry }) {
  return (
    <div className="state state-error" role="alert">
      <div className="state-icon" aria-hidden="true">!</div>
      <h3>Could not load this section</h3>
      <p>{message}</p>
      {onRetry && <Button variant="secondary" onClick={onRetry}>Try again</Button>}
    </div>
  );
}
