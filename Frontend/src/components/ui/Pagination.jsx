import Button from './Button';

function Pagination({ page, pages, total, onPage, noun = 'results' }) {
  return (
    <nav className="pagination" aria-label="Pagination">
      <p className="muted" aria-live="polite">{total} {noun} · page {page} of {pages}</p>
      <div className="row gap">
        <Button variant="secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous<span className="sr-only"> page</span></Button>
        <Button variant="secondary" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next<span className="sr-only"> page</span></Button>
      </div>
    </nav>
  );
}

export default Pagination;
