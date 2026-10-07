import { useId, useRef } from 'react';

// Six single-digit boxes: auto-advance, backspace goes back, arrows move, paste fills all boxes.
function OtpInput({ value, onChange, onComplete, length = 6, label = 'Verification code', error, disabled = false, autoFocus = false }) {
  const refs = useRef([]);
  const groupId = useId();
  const digits = Array.from({ length }, (_, i) => value[i] || '');

  const focusAt = (i) => refs.current[Math.max(0, Math.min(length - 1, i))]?.focus();

  const commit = (next) => {
    const clean = next.replace(/\D/g, '').slice(0, length);
    onChange(clean);
    if (clean.length === length) onComplete?.(clean);
    return clean;
  };

  const handleChange = (i, e) => {
    const typed = e.target.value.replace(/\D/g, '');
    if (!typed) return;
    const chars = digits.slice();
    // typing next to a filled digit keeps only the new one; longer input (autofill) spreads forward
    let incoming = typed;
    if (digits[i] && typed.length === 2) incoming = typed[0] === digits[i] ? typed[1] : typed[0];
    for (let k = 0; k < incoming.length && i + k < length; k++) chars[i + k] = incoming[k];
    commit(chars.join(''));
    focusAt(Math.min(i + incoming.length, length - 1));
  };

  const handleKeyDown = (i, e) => {
    if (e.key === 'Backspace') {
      e.preventDefault();
      const chars = digits.slice();
      if (chars[i]) { chars[i] = ''; } else if (i > 0) { chars[i - 1] = ''; focusAt(i - 1); }
      onChange(chars.join('').slice(0, length));
    } else if (e.key === 'ArrowLeft') { e.preventDefault(); focusAt(i - 1); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); focusAt(i + 1); }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const text = e.clipboardData.getData('text');
    const clean = commit(text);
    focusAt(clean.length >= length ? length - 1 : clean.length);
  };

  return (
    <div className={`otp${error ? ' has-error' : ''}`} role="group" aria-labelledby={`${groupId}-l`} aria-describedby={error ? `${groupId}-e` : undefined}>
      <span className="otp-label" id={`${groupId}-l`}>{label}</span>
      <div className="otp-boxes">
        {digits.map((d, i) => (
          <input
            key={i}
            ref={(el) => { refs.current[i] = el; }}
            className="otp-box"
            inputMode="numeric"
            pattern="[0-9]*"
            autoComplete={i === 0 ? 'one-time-code' : 'off'}
            maxLength={length}
            value={d}
            disabled={disabled}
            autoFocus={autoFocus && i === 0}
            aria-label={`${label}, digit ${i + 1} of ${length}`}
            aria-invalid={error ? true : undefined}
            onChange={(e) => handleChange(i, e)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            onPaste={handlePaste}
            onFocus={(e) => e.target.select()}
          />
        ))}
      </div>
      {error && <p className="error-text" id={`${groupId}-e`}>{error}</p>}
    </div>
  );
}

export default OtpInput;
