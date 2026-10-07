// variant: primary | secondary | ghost | danger. `loading` disables the button and shows a spinner.
function Button({ variant = 'primary', loading = false, disabled = false, type = 'button', className = '', children, ...rest }) {
  return (
    <button
      type={type}
      className={`btn btn-${variant}${className ? ` ${className}` : ''}`}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading && <span className="spinner" aria-hidden="true" />}
      <span>{children}</span>
    </button>
  );
}

export default Button;
