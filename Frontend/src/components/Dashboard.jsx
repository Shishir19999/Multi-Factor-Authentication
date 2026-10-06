import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { getToken, clearToken } from '../auth/auth';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const Dashboard = () => {
  const [user, setUser] = useState(null);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // Revoke the token on the server (best effort), then clear it locally.
  const logout = async () => {
    try {
      await axios.post(`${API_URL}/auth/logout`, null, { headers: { Authorization: `Bearer ${getToken()}` } });
    } catch {
      /* token already invalid or server unreachable: sign out locally anyway */
    }
    clearToken();
    navigate('/login', { replace: true });
  };

  useEffect(() => {
    axios
      .get(`${API_URL}/auth/me`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((res) => setUser(res.data.user))
      .catch((err) => {
        if (err.response && err.response.status === 401) {
          clearToken();
          navigate('/login', { replace: true });
        } else {
          setError('Could not load your profile');
        }
      });
  }, [navigate]);

  return (
    <div className="dashboard">
      <h2>Dashboard</h2>
      {error && <p>{error}</p>}
      {user ? <p>Signed in as <strong>{user.email}</strong></p> : !error && <p>Loading...</p>}
      <button onClick={logout}>Logout</button>
    </div>
  );
};

export default Dashboard;
