import { useEffect } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import Landing from '../pages/Landing';
import Login from '../pages/Login';
import Register from '../pages/Register';
import Recover from '../pages/Recover';
import Dashboard from '../pages/Dashboard';
import NotFound from '../pages/NotFound';
import ProtectedRoute from '../auth/ProtectedRoute';

const TITLES = {
  '/': 'Home',
  '/login': 'Sign in',
  '/register': 'Create account',
  '/recover': 'Recover account',
  '/dashboard': 'Security dashboard',
};

// Updates the document title and scrolls to the top on navigation.
function RouteEffects() {
  const { pathname } = useLocation();
  useEffect(() => {
    document.title = `${TITLES[pathname] || 'Page not found'} · Multi Factor Authentication`;
    window.scrollTo(0, 0);
  }, [pathname]);
  return null;
}

function RouterComponent() {
  return (
    <>
      <RouteEffects />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Registration />} />
        <Route path="/recover" element={<Recover />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  );
}

const Registration = Register;

export default RouterComponent;
