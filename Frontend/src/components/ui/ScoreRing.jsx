// Circular security score. The number and grade are text, so colour is never the only signal.
function ScoreRing({ score, grade, label, size = 132 }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const tone = score >= 75 ? 'good' : score >= 55 ? 'fair' : 'poor';
  return (
    <div className={`score-ring ${tone}`} role="img" aria-label={`Security score ${score} out of 100, grade ${grade}, ${label}`} style={{ width: size, height: size }}>
      <svg viewBox="0 0 120 120" width={size} height={size} aria-hidden="true" focusable="false">
        <circle cx="60" cy="60" r={r} className="ring-track" />
        <circle cx="60" cy="60" r={r} className="ring-value" strokeDasharray={`${(score / 100) * c} ${c}`} transform="rotate(-90 60 60)" />
      </svg>
      <div className="ring-text" aria-hidden="true"><strong>{score}</strong><span>{grade} · {label}</span></div>
    </div>
  );
}

export default ScoreRing;
