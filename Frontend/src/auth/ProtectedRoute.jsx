import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/contexts';
import { Loading } from '../components/ui/States';

function ProtectedRoute({ children }) {
  const location = useLocation();
  const { status } = useAuth();
  if (status === 'loading') {
    return <div className="container section"><Loading label="Checking your session" lines={5} /></div>;
  }
  if (status !== 'authed') {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return children;
}

export default ProtectedRoute;
