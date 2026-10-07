// Scroll motion: reveal-on-scroll and parallax. Only transform/opacity are animated, work is batched in
// requestAnimationFrame, and everything is switched off for prefers-reduced-motion. Parallax is also off on
// small screens and on low-power / data-saver devices. No scroll hijacking: scrolling itself is never touched.
const hasWindow = typeof window !== 'undefined';
const mq = (q) => (hasWindow && window.matchMedia ? window.matchMedia(q) : { matches: false, addEventListener() {}, removeEventListener() {} });

const reduceMotion = mq('(prefers-reduced-motion: reduce)');
const smallScreen = mq('(max-width: 719px)');

export function isLowPower(nav = hasWindow ? navigator : {}) {
  return !!(nav.connection?.saveData || (nav.deviceMemory && nav.deviceMemory <= 2) || (nav.hardwareConcurrency && nav.hardwareConcurrency <= 2));
}

export const motionAllowed = () => !reduceMotion.matches;
export const parallaxAllowed = () => !reduceMotion.matches && !smallScreen.matches && !isLowPower();

// Pure helper (unit-tested): vertical shift for an element whose centre is `offset` px from the viewport centre.
export function parallaxShift(offset, speed, max = 60) {
  const shift = -offset * speed;
  return Math.max(-max, Math.min(max, shift));
}

const parallaxItems = new Set();
const visible = new Set();
let frame = 0;
let io;

function resetAll() {
  parallaxItems.forEach((it) => { it.inner.style.transform = ''; });
}

function update() {
  frame = 0;
  if (!parallaxAllowed()) { resetAll(); return; }
  const half = window.innerHeight / 2;
  visible.forEach((it) => {
    const r = it.wrapper.getBoundingClientRect();
    const shift = parallaxShift(r.top + r.height / 2 - half, it.speed);
    it.inner.style.transform = `translate3d(0, ${shift.toFixed(1)}px, 0)`;
  });
}

const schedule = () => { if (!frame) frame = requestAnimationFrame(update); };

function ensureObserver() {
  if (io || !hasWindow) return;
  io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      const item = [...parallaxItems].find((it) => it.wrapper === e.target);
      if (!item) return;
      if (e.isIntersecting) visible.add(item); else visible.delete(item);
    });
    schedule();
  }, { rootMargin: '120px 0px' });
  window.addEventListener('scroll', schedule, { passive: true });
  window.addEventListener('resize', schedule, { passive: true });
  reduceMotion.addEventListener('change', schedule);
  smallScreen.addEventListener('change', schedule);
}

export function registerParallax(wrapper, inner, speed = 0.15) {
  ensureObserver();
  const item = { wrapper, inner, speed };
  parallaxItems.add(item);
  io.observe(wrapper);
  schedule();
  return () => {
    io.unobserve(wrapper);
    parallaxItems.delete(item);
    visible.delete(item);
    inner.style.transform = '';
  };
}

// Reveal: elements get `.is-revealed` once, the first time they enter the viewport.
let revealIo;
export function observeReveal(el) {
  if (!hasWindow || !('IntersectionObserver' in window)) { el.classList.add('is-revealed'); return () => {}; }
  revealIo ??= new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add('is-revealed'); revealIo.unobserve(e.target); }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
  revealIo.observe(el);
  return () => revealIo.unobserve(el);
}

// Reflects the motion preference on <html data-motion="on|off"> so CSS can hide reveal targets only when animating.
export function initMotion() {
  if (!hasWindow) return () => {};
  const apply = () => { document.documentElement.dataset.motion = motionAllowed() ? 'on' : 'off'; };
  apply();
  reduceMotion.addEventListener('change', apply);
  return () => reduceMotion.removeEventListener('change', apply);
}
