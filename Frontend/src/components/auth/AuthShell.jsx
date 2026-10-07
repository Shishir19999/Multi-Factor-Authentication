import { Parallax } from '../ui/Motion';

// Page frame for sign-in, sign-up and recovery: a form card with a calm decorative backdrop.
function AuthShell({ children, aside }) {
  return (
    <div className="auth-page">
      <Parallax speed={0.12} className="auth-blob auth-blob-a"><span /></Parallax>
      <Parallax speed={-0.1} className="auth-blob auth-blob-b"><span /></Parallax>
      <div className="container auth-grid">
        <div className="card auth-card">{children}</div>
        {aside}
      </div>
    </div>
  );
}

export default AuthShell;
