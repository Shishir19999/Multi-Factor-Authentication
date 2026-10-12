// Page frame for sign-in, sign-up and recovery: a form card with a calm, static decorative backdrop.
// (Parallax is reserved for the landing page; forms and security screens never move.)
function AuthShell({ children, aside }) {
  return (
    <div className="auth-page">
      <div className="auth-blob auth-blob-a" aria-hidden="true"><span /></div>
      <div className="auth-blob auth-blob-b" aria-hidden="true"><span /></div>
      <div className="container auth-grid">
        <div className="card auth-card">{children}</div>
        {aside}
      </div>
    </div>
  );
}

export default AuthShell;
