import { useEffect, useRef } from 'react';
import { observeReveal, registerParallax } from '../../lib/motion';

// Fades/slides its children in the first time they scroll into view (disabled by reduced-motion).
export function Reveal({ as: Tag = 'div', delay = 0, className = '', children, ...rest }) {
  const ref = useRef(null);
  useEffect(() => observeReveal(ref.current), []);
  return (
    <Tag ref={ref} className={`reveal${className ? ` ${className}` : ''}`} style={{ '--reveal-delay': `${delay}ms` }} {...rest}>
      {children}
    </Tag>
  );
}

// Decorative layer that drifts slightly slower/faster than the page while scrolling. Never wraps interactive content.
export function Parallax({ speed = 0.15, className = '', children }) {
  const wrapper = useRef(null);
  const inner = useRef(null);
  useEffect(() => registerParallax(wrapper.current, inner.current, speed), [speed]);
  return (
    <div ref={wrapper} className={`parallax ${className}`} aria-hidden="true">
      <div ref={inner} className="parallax-inner">{children}</div>
    </div>
  );
}
