// Inline message. type: error | success | info | warning. Errors are announced immediately.
function Alert({ type = 'info', children, className = '' }) {
  return (
    <div className={`alert alert-${type}${className ? ` ${className}` : ''}`} role={type === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  );
}

export default Alert;
