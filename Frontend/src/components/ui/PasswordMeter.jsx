import { passwordRules, passwordStrength } from '../../lib/password';

// Live strength meter plus the rules checklist. Rules are text + icon, never colour alone.
function PasswordMeter({ password }) {
  const strength = passwordStrength(password);
  const rules = passwordRules(password);
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
    </div>
  );
}

export default PasswordMeter;
