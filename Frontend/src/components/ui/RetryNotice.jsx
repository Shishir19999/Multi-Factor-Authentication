import { formatDuration } from '../../lib/format';

// Visible countdown for rate limits and lockouts. The ticking digits are hidden from screen readers (they would
// announce every second); a coarse, rarely-changing sentence is announced instead.
function RetryNotice({ seconds, title, children }) {
  if (seconds <= 0) return null;
  const minutes = Math.ceil(seconds / 60);
  return (
    <div className="alert alert-warning retry-notice" role="status">
      <p className="retry-title"><strong>{title}</strong></p>
      {children && <p>{children}</p>}
      <p>
        Try again in <span className="countdown" aria-hidden="true">{formatDuration(seconds)}</span>
        <span className="sr-only">about {minutes} minute{minutes === 1 ? '' : 's'}</span>.
      </p>
    </div>
  );
}

export default RetryNotice;
