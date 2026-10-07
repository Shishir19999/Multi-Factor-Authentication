import { Link } from 'react-router-dom';

function NotFound() {
  return (
    <div className="container not-found">
      <p className="eyebrow">Error 404</p>
      <h1>This page does not exist</h1>
      <p className="muted">The address may be mistyped or the page may have moved.</p>
      <div className="row gap">
        <Link to="/" className="btn btn-primary">Go to the home page</Link>
        <Link to="/login" className="btn btn-secondary">Sign in</Link>
      </div>
    </div>
  );
}

export default NotFound;
