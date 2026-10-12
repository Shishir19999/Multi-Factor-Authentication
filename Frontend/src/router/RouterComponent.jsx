import { useEffect } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import Landing from '../pages/Landing';
import Login from '../pages/Login';
import Register from '../pages/Register';
import Recover from '../pages/Recover';
import Review from '../pages/Review';
import Dashboard from '../pages/Dashboard';
import Admin from '../pages/Admin';
import NotFound from '../pages/NotFound';
import ProtectedRoute from '../auth/ProtectedRoute';

const TITLES = {
  '/': 'Home',
  '/login': 'Sign in',
  '/register': 'Create account',
  '/recover': 'Recover account',
  '/review': 'Was this you?',
  '/dashboard': 'Security dashboard',
  '/admin': 'Admin console',
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
        <Route path="/register" element={<Register />} />
        <Route path="/recover" element={<Recover />} />
        <Route path="/review" element={<Review />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  );
}

export default RouterComponent;
