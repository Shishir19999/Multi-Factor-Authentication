import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth, useTheme, useToast } from '../../context/contexts';
import { APP_NAME } from '../../config';

export function ShieldLogo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path d="M16 2.5 4.5 6.8v8.1c0 7 4.8 12.4 11.5 14.6 6.7-2.2 11.5-7.6 11.5-14.6V6.8L16 2.5Z" fill="var(--primary)" />
      <path d="m10.8 16.2 3.9 3.9 6.6-7.4" fill="none" stroke="var(--on-primary)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const dark = theme === 'dark';
  return (
    <button type="button" className="icon-btn" onClick={toggle} aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'} title={dark ? 'Light theme' : 'Dark theme'}>
      {dark ? (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
          <circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      ) : (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />
        </svg>
      )}
    </button>
  );
}

function Header() {
  const { user, status, signOut } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();

  const handleSignOut = async () => {
    await signOut();
    toast('You have been signed out.', 'success');
    navigate('/login', { replace: true });
  };

  return (
    <header className="site-header">
      <div className="container header-row">
        <Link to="/" className="brand" aria-label={`${APP_NAME} home`}>
          <ShieldLogo />
          <span className="brand-name">{APP_NAME}</span>
        </Link>
        <nav className="nav" aria-label="Main">
          {status === 'authed' && user ? (
            <>
              <NavLink to="/dashboard" className="nav-link">Dashboard</NavLink>
              <button type="button" className="nav-link nav-btn" onClick={handleSignOut}>Sign out</button>
            </>
          ) : (
            <>
              <NavLink to="/login" className="nav-link">Sign in</NavLink>
              <NavLink to="/register" className="nav-link nav-cta">Create account</NavLink>
            </>
          )}
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}

export default Header;
