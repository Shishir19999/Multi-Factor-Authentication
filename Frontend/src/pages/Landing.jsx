import { Link } from 'react-router-dom';
import { IS_PREVIEW } from '../config';
import { useAuth } from '../context/contexts';
import { Parallax, Reveal } from '../components/ui/Motion';

const FEATURES = [
  { icon: '✉', title: 'E-mail one-time codes', text: 'A 6-digit code valid for five minutes, with attempt limits and a resend cooldown.' },
  { icon: '⏱', title: 'Authenticator app (TOTP)', text: 'Standard RFC 6238 codes. Scan the QR code with Google Authenticator or any compatible app.' },
  { icon: '🔑', title: 'Passkeys (WebAuthn)', text: 'Sign in with a fingerprint, screen lock or security key. Phishing-resistant, no password typed.' },
  { icon: '🗝', title: 'Backup and recovery', text: 'Single-use backup codes, a verified recovery e-mail and administrator-assisted recovery.' },
  { icon: '✔', title: 'Step-up confirmation', text: 'Sensitive changes ask you to confirm it is you again, with a password, a code or a passkey.' },
  { icon: '⚑', title: 'Was this you?', text: 'A new device or place triggers an alert e-mail with one-tap "yes" or "secure my account".' },
  { icon: '★', title: 'Security score', text: 'A 0 to 100 score with ranked recommendations tells you what to fix first.' },
  { icon: '▤', title: 'Sessions and devices', text: 'Name your devices, see where you are signed in and sign out one, the others or everywhere.' },
  { icon: '◷', title: 'Activity and export', text: 'A timeline of sign-ins and security changes, exportable as CSV or JSON.' },
  { icon: '⚿', title: 'Breached-password check', text: 'Optional k-anonymity lookup: only the first 5 characters of a hash ever leave your browser.' },
  { icon: '⌘', title: 'Personal API tokens', text: 'Scoped, read-only tokens that are stored only as a hash and can be revoked at once.' },
  { icon: '⚙', title: 'Admin console and policy', text: 'Users, lock and unlock, forced resets, an audit log with CSV export and configurable security rules.' },
];

const STEPS = [
  { n: 1, title: 'Create an account', text: 'Choose a password and watch the strength meter and the policy rules update as you type.' },
  { n: 2, title: 'Pick your second step', text: 'Receive codes by e-mail, scan a QR code for an authenticator app, or add a passkey.' },
  { n: 3, title: 'Stay in control', text: 'Follow the score, review sessions and alerts, export your activity and rotate backup codes.' },
];

const ROLES = [
  { title: 'Member', text: 'Manages their own sign-in methods, devices, recovery options, activity and API tokens.' },
  { title: 'Administrator', text: 'Everything a member can do, plus the console: users, lock and unlock, forced resets, help requests, the audit log and the security policy.' },
];

function Landing() {
  const { status } = useAuth();
  const signedIn = status === 'authed';

  return (
    <div className="landing">
      <section className="hero">
        <Parallax speed={0.18} className="hero-bg hero-bg-a"><span /></Parallax>
        <Parallax speed={-0.12} className="hero-bg hero-bg-b"><span /></Parallax>
        <div className="container hero-grid">
          <div className="hero-copy">
            <Reveal as="p" className="eyebrow">Account security</Reveal>
            <Reveal as="h1" delay={80}>Sign-in security you can see working</Reveal>
            <Reveal as="p" delay={160} className="lead">
              Password plus an e-mail code, an authenticator app or a passkey, with alerts, recovery options, session control, a security score and an admin console.
            </Reveal>
            <Reveal delay={240} className="row gap wrap">
              {signedIn ? (
                <Link to="/dashboard" className="btn btn-primary">Open your dashboard</Link>
              ) : (
                <>
                  <Link to={IS_PREVIEW ? '/login' : '/register'} className="btn btn-primary">{IS_PREVIEW ? 'Try the Live preview' : 'Create an account'}</Link>
                  <Link to={IS_PREVIEW ? '/register' : '/login'} className="btn btn-secondary">{IS_PREVIEW ? 'Create a sample account' : 'Sign in'}</Link>
                </>
              )}
            </Reveal>
          </div>
          <Reveal delay={200} className="hero-visual">
            <Parallax speed={0.08} className="hero-card-wrap">
              <div className="hero-card">
                <p className="hero-card-title">Enter your code</p>
                <div className="fake-otp" aria-hidden="true">
                  {['4', '8', '2', '0', '1', '7'].map((d, i) => <span key={i}>{d}</span>)}
                </div>
                <p className="hero-card-foot">Changes every 30 seconds</p>
              </div>
            </Parallax>
          </Reveal>
        </div>
      </section>

      <section className="section" aria-labelledby="features-title">
        <div className="container">
          <Reveal><h2 id="features-title" className="section-title">Everything a secure sign-in needs</h2></Reveal>
          <ul className="feature-grid">
            {FEATURES.map((f, i) => (
              <Reveal as="li" key={f.title} delay={(i % 4) * 70} className="card feature">
                <span className="feature-icon" aria-hidden="true">{f.icon}</span>
                <h3>{f.title}</h3>
                <p>{f.text}</p>
              </Reveal>
            ))}
          </ul>
        </div>
      </section>

      <section className="section section-alt" aria-labelledby="how-title">
        <Parallax speed={0.1} className="section-bg"><span /></Parallax>
        <div className="container">
          <Reveal><h2 id="how-title" className="section-title">How it works</h2></Reveal>
          <ol className="steps">
            {STEPS.map((s, i) => (
              <Reveal as="li" key={s.n} delay={i * 90} className="card step">
                <span className="step-n" aria-hidden="true">{s.n}</span>
                <h3>{s.title}</h3>
                <p>{s.text}</p>
              </Reveal>
            ))}
          </ol>
        </div>
      </section>

      <section className="section" aria-labelledby="roles-title">
        <div className="container">
          <Reveal><h2 id="roles-title" className="section-title">Two roles</h2></Reveal>
          <ul className="steps">
            {ROLES.map((r, i) => (
              <Reveal as="li" key={r.title} delay={i * 90} className="card step">
                <h3>{r.title}</h3>
                <p>{r.text}</p>
              </Reveal>
            ))}
          </ul>
        </div>
      </section>

      <section className="section cta-band">
        <div className="container">
          <Reveal>
            <h2>{IS_PREVIEW ? 'Everything runs in your browser' : 'Ready to secure your account?'}</h2>
            <p className="lead">
              {IS_PREVIEW
                ? 'The Live preview uses sample accounts and stores data only in this browser. Reset it whenever you like.'
                : 'Create an account and turn on two-step verification in under a minute.'}
            </p>
            <Link to={signedIn ? '/dashboard' : IS_PREVIEW ? '/login' : '/register'} className="btn btn-primary">
              {signedIn ? 'Open your dashboard' : IS_PREVIEW ? 'Open the Live preview' : 'Get started'}
            </Link>
          </Reveal>
        </div>
      </section>
    </div>
  );
}

export default Landing;
