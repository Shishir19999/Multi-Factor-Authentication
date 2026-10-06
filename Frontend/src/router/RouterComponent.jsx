import { Routes, Route } from 'react-router-dom';
import Login from '../components/User Crediantials/Login';
import Registration from '../components/User Crediantials/Registration';
import Dashboard from '../components/Dashboard';
import ProtectedRoute from '../auth/ProtectedRoute';


function RouterComponent() {
  return (
    <div>
      <Routes>
      <Route path="/" element={<Login/>} />
      <Route path="/login" element={<Login/>} />
      <Route path="/register" element={<Registration/>} />
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard/></ProtectedRoute>} />

      </Routes>
    </div>
  )
}

export default RouterComponent
