import { Link } from 'react-router-dom';
import { IS_DEMO } from '../config';
import { useAuth } from '../context/contexts';
import { Parallax, Reveal } from '../components/ui/Motion';

const FEATURES = [
  { icon: '✉', title: 'E-mail one-time codes', text: 'A 6-digit code valid for five minutes, with attempt limits and a resend cooldown.' },
  { icon: '⏱', title: 'Authenticator app (TOTP)', text: 'Standard RFC 6238 codes. Scan the QR code with Google Authenticator or any compatible app.' },
  { icon: '🗝', title: 'Backup codes', text: 'Ten single-use codes for when your phone is gone. Download or print them once.' },
  { icon: '✔', title: 'Trusted devices', text: 'Skip the second step on a device you trust for 30 days, and forget it any time.' },
  { icon: '▤', title: 'Active sessions', text: 'See where you are signed in and revoke any session with one click.' },
  { icon: '◷', title: 'Sign-in log', text: 'A timeline of successful and failed attempts so unusual activity stands out.' },
  { icon: '⚑', title: 'Lockout protection', text: 'Repeated wrong passwords lock the account for a while, with clear countdown messaging.' },
  { icon: '↺', title: 'Account recovery', text: 'Reset a forgotten password with an e-mailed code. All other sessions are signed out.' },
];

const STEPS = [
  { n: 1, title: 'Create an account', text: 'Choose a password and watch the strength meter and rules update as you type.' },
  { n: 2, title: 'Pick a second factor', text: 'Receive codes by e-mail, or scan a QR code to use an authenticator app.' },
  { n: 3, title: 'Stay in control', text: 'Review sessions and activity, change your password and rotate backup codes.' },
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
            <Reveal as="p" className="eyebrow">Two-step verification</Reveal>
            <Reveal as="h1" delay={80}>Sign-in security you can see working</Reveal>
            <Reveal as="p" delay={160} className="lead">
              Password plus a one-time code from your e-mail or an authenticator app, with backup codes, session control and a full sign-in history.
            </Reveal>
            <Reveal delay={240} className="row gap wrap">
              {signedIn ? (
                <Link to="/dashboard" className="btn btn-primary">Open your dashboard</Link>
              ) : (
                <>
                  <Link to={IS_DEMO ? '/login' : '/register'} className="btn btn-primary">{IS_DEMO ? 'Try the live demo' : 'Create an account'}</Link>
                  <Link to={IS_DEMO ? '/register' : '/login'} className="btn btn-secondary">{IS_DEMO ? 'Create a demo account' : 'Sign in'}</Link>
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

      <section className="section cta-band">
        <div className="container">
          <Reveal>
            <h2>{IS_DEMO ? 'Everything runs in your browser' : 'Ready to secure your account?'}</h2>
            <p className="lead">
              {IS_DEMO
                ? 'The demo uses sample accounts and stores data only in this browser. Reset it whenever you like.'
                : 'Create an account and turn on two-step verification in under a minute.'}
            </p>
            <Link to={signedIn ? '/dashboard' : IS_DEMO ? '/login' : '/register'} className="btn btn-primary">
              {signedIn ? 'Open your dashboard' : IS_DEMO ? 'Open the demo' : 'Get started'}
            </Link>
          </Reveal>
        </div>
      </section>
    </div>
  );
}

export default Landing;
