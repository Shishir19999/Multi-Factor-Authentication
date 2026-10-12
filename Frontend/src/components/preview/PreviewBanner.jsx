import { useConfirm, useToast } from '../../context/contexts';
import { resetPreviewData } from '../../api/previewStore';

// Shown only in the Live preview build: explains where data lives and offers a reset.
function PreviewBanner() {
  const { confirm } = useConfirm();
  const { toast } = useToast();

  const reset = async () => {
    const ok = await confirm({
      title: 'Reset preview data?',
      message: 'This restores the sample accounts and deletes any accounts, sessions, trusted devices, simulated passkeys and inbox messages you created in this browser.',
      confirmLabel: 'Reset preview data',
      danger: true,
    });
    if (!ok) return;
    resetPreviewData();
    toast('Preview data was reset.', 'success');
    window.location.hash = '#/login';
    window.location.reload();
  };

  return (
    <div className="preview-banner" role="region" aria-label="Live preview">
      <div className="container preview-banner-row">
        <p>
          <strong>Live preview.</strong> Everything stays in your browser (localStorage). No server is contacted and no e-mail is sent: messages appear in the Preview inbox, and locations are simulated.
        </p>
        <button type="button" className="link-btn" onClick={reset}>Reset preview data</button>
      </div>
    </div>
  );
}

export default PreviewBanner;
