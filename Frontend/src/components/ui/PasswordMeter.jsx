import { useState } from 'react';
import { PasswordField } from './Field';
import { passwordRules, passwordStrength } from '../../lib/password';
import { usePolicy } from '../../context/contexts';
import { breachPrefOn, setBreachPref, useBreachCheck } from '../../hooks/useBreachCheck';

const BREACH_TEXT = {
  checking: 'Checking known data breaches...',
  safe: 'Not found in known data breaches.',
  unavailable: 'Could not check known breaches (offline?). The server may still check it.',
};

// Live strength meter, the rules checklist (from the active policy) and the breach result. Rules are text + icon, never colour alone.
function PasswordMeter({ password, policy, email, breach }) {
  const strength = passwordStrength(password, policy, { email });
  const rules = passwordRules(password, policy, { email });
  return (
    <div className="pw-meter">
      <div className="pw-bars" role="meter" aria-label="Password strength" aria-valuemin={0} aria-valuemax={4} aria-valuenow={strength.score} aria-valuetext={strength.label}>
        {[1, 2, 3, 4].map((n) => (
          <span key={n} className={`pw-bar${!strength.empty && strength.score >= n ? ` on s${strength.score}` : ''}`} />
        ))}
      </div>
      <p className="pw-label" aria-live="polite">Strength: <strong>{strength.label}</strong></p>
      <ul className="pw-rules">
        {rules.map((r) => (
          <li key={r.id} className={r.ok ? 'ok' : ''}>
            <span aria-hidden="true">{r.ok ? '✓' : '○'}</span> {r.label}
            <span className="sr-only">{r.ok ? ' (met)' : ' (not met yet)'}</span>
          </li>
        ))}
      </ul>
      <p className={`pw-breach${breach?.state === 'pwned' ? ' bad' : ''}`} aria-live="polite">
        {breach?.state === 'pwned'
          ? `Found in ${breach.count.toLocaleString('en-US')} known data breaches. Choose a different password.`
          : (BREACH_TEXT[breach?.state] || '')}
      </p>
    </div>
  );
}

// Password input + meter + optional breach check (Have I Been Pwned, k-anonymity). Used wherever a new password is chosen.
export function PasswordCreate({ label = 'Password', value, onChange, onBlur, error, email, autoComplete = 'new-password' }) {
  const { policy } = usePolicy();
  const [pref, setPref] = useState(breachPrefOn);
  const available = policy.breachCheck !== 'off';
  const breach = useBreachCheck(value, available && pref);
  return (
    <div className="stack-sm">
      <PasswordField label={label} autoComplete={autoComplete} value={value} onChange={onChange} onBlur={onBlur} error={error} />
      <PasswordMeter password={value} policy={policy} email={email} breach={breach} />
      {available && (
        <label className="check check-sm">
          <input type="checkbox" checked={pref} onChange={(e) => { setPref(e.target.checked); setBreachPref(e.target.checked); }} />
          <span>Check against known data breaches. Only the first 5 characters of a hash of the password are sent, never the password.</span>
        </label>
      )}
    </div>
  );
}

export default PasswordMeter;
