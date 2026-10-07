import { useMemo } from 'react';
import { qrMatrix, qrPath } from '../../lib/qr';

// Renders the otpauth:// URL as an SVG QR code entirely in the browser. Always dark-on-white so scanners can read it.
function QrCode({ value, label = 'QR code', size = 200 }) {
  const { d, size: units } = useMemo(() => qrPath(qrMatrix(value)), [value]);
  return (
    <svg className="qr" role="img" aria-label={label} width={size} height={size} viewBox={`0 0 ${units} ${units}`} shapeRendering="crispEdges">
      <rect width={units} height={units} fill="#ffffff" />
      <path d={d} fill="#000000" />
    </svg>
  );
}

export default QrCode;
