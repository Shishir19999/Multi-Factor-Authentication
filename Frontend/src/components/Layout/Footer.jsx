import { IS_DEMO, REPO_URL } from '../../config';

function Footer() {
  return (
    <footer className="site-footer">
      <div className="container footer-row">
        <p>
          {IS_DEMO
            ? 'Browser-only demo. Sample data, nothing is sent to a server.'
            : 'Two-step verification with e-mail codes or an authenticator app.'}
        </p>
        <a href={REPO_URL} target="_blank" rel="noopener noreferrer">Source on GitHub</a>
      </div>
    </footer>
  );
}

export default Footer;
