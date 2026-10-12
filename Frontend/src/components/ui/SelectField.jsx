import { useId } from 'react';

// Labelled <select>. options: [{ value, label }] or plain strings.
function SelectField({ label, value, onChange, options, hint, className = '', ...rest }) {
  const id = useId();
  return (
    <div className={`field${className ? ` ${className}` : ''}`}>
      <label htmlFor={id}>{label}</label>
      <select id={id} className="input" value={value} onChange={onChange} aria-describedby={hint ? `${id}-hint` : undefined} {...rest}>
        {options.map((o) => {
          const opt = typeof o === 'string' ? { value: o, label: o } : o;
          return <option key={opt.value} value={opt.value}>{opt.label}</option>;
        })}
      </select>
      {hint && <p className="hint" id={`${id}-hint`}>{hint}</p>}
    </div>
  );
}

export default SelectField;
