import { useConfirm, useToast } from '../../context/contexts';
import { resetDemoData } from '../../api/demoStore';

// Shown only in the browser-only build: explains where data lives and offers a reset.
function DemoBanner() {
  const { confirm } = useConfirm();
  const { toast } = useToast();

  const reset = async () => {
    const ok = await confirm({
      title: 'Reset demo data?',
      message: 'This restores the sample accounts and deletes any accounts, sessions, trusted devices and inbox messages you created in this browser.',
      confirmLabel: 'Reset demo data',
      danger: true,
    });
    if (!ok) return;
    resetDemoData();
    toast('Demo data was reset.', 'success');
    window.location.hash = '#/login';
    window.location.reload();
  };

  return (
    <div className="demo-banner" role="region" aria-label="Demo mode">
      <div className="container demo-banner-row">
        <p>
          <strong>Demo mode.</strong> Everything stays in your browser (localStorage). No server is contacted and no e-mail is sent; codes appear in the Demo inbox.
        </p>
        <button type="button" className="link-btn" onClick={reset}>Reset demo data</button>
      </div>
    </div>
  );
}

export default DemoBanner;
