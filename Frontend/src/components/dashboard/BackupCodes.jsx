import { useToast } from '../../context/contexts';
import { downloadText } from '../../lib/download';
import { formatBackupCodes } from '../../lib/format';
import Button from '../ui/Button';

// Shows newly created backup codes once, with download / print / copy.
function BackupCodes({ codes, email }) {
  const { toast } = useToast();
  const text = `Backup codes for ${email}\nEach code works once. Keep them somewhere safe.\n\n${formatBackupCodes(codes)}\n`;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast('Backup codes copied.', 'success');
    } catch {
      toast('Could not copy automatically. Use Download instead.', 'error');
    }
  };

  return (
    <div className="stack">
      <div className="print-area">
        <p className="print-title">Backup codes for {email}</p>
        <ol className="backup-list">
          {codes.map((c) => <li key={c}><code>{c}</code></li>)}
        </ol>
      </div>
      <div className="row gap wrap">
        <Button variant="secondary" onClick={() => downloadText('backup-codes.txt', text)}>Download</Button>
        <Button variant="secondary" onClick={() => window.print()}>Print</Button>
        <Button variant="secondary" onClick={copy}>Copy</Button>
      </div>
      <p className="muted">Each code works once. They will not be shown again, so store them somewhere safe.</p>
    </div>
  );
}

export default BackupCodes;
