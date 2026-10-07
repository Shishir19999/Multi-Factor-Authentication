import qrcode from 'qrcode-generator';

// Encodes text as a QR code and returns the module matrix (true = dark). Rendered client-side, nothing leaves the browser.
export function qrMatrix(text, errorCorrection = 'M') {
  const qr = qrcode(0, errorCorrection);
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => qr.isDark(r, c)));
}

// One SVG path covering all dark modules (horizontal runs merged), with a 4-module quiet zone.
export function qrPath(matrix, quiet = 4) {
  let d = '';
  matrix.forEach((row, y) => {
    let x = 0;
    while (x < row.length) {
      if (!row[x]) { x++; continue; }
      const start = x;
      while (x < row.length && row[x]) x++;
      d += `M${start + quiet} ${y + quiet}h${x - start}v1h-${x - start}z`;
    }
  });
  return { d, size: matrix.length + quiet * 2 };
}
