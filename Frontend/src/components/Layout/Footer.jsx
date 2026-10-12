import { IS_PREVIEW, REPO_URL } from '../../config';

function Footer() {
  return (
    <footer className="site-footer">
      <div className="container footer-row">
        <p>
          {IS_PREVIEW
            ? 'Live preview in your browser. Sample data only, nothing is sent to a server.'
            : 'Account security with two-step verification, passkeys and an admin console.'}
        </p>
        <a href={REPO_URL} target="_blank" rel="noopener noreferrer">Source on GitHub</a>
      </div>
    </footer>
  );
}

export default Footer;
