import { useCallback, useMemo, useRef, useState } from 'react';
import { ConfirmContext } from './contexts';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';

// confirm({ title, message, confirmLabel, danger }) resolves to true/false; used before destructive actions.
function ConfirmProvider({ children }) {
  const [state, setState] = useState(null);
  const resolver = useRef(null);

  const confirm = useCallback((options) => new Promise((resolve) => {
    resolver.current = resolve;
    setState(options);
  }), []);

  const finish = (answer) => {
    resolver.current?.(answer);
    resolver.current = null;
    setState(null);
  };

  const value = useMemo(() => ({ confirm }), [confirm]);

  return (
    <ConfirmContext.Provider value={value}>
      {children}
      <Modal
        open={!!state}
        title={state?.title || 'Are you sure?'}
        onClose={() => finish(false)}
        footer={(
          <>
            <Button variant="ghost" onClick={() => finish(false)}>Cancel</Button>
            <Button variant={state?.danger ? 'danger' : 'primary'} onClick={() => finish(true)}>{state?.confirmLabel || 'Confirm'}</Button>
          </>
        )}
      >
        <p>{state?.message}</p>
      </Modal>
    </ConfirmContext.Provider>
  );
}

export default ConfirmProvider;
