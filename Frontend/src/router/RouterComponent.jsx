import React from 'react'
import { Routes, Route } from 'react-router-dom';
import Login from '../components/User Crediantials/Login';
import Registration from '../components/User Crediantials/Registration';


function RouterComponent() {
  return (
    <div>
      <Routes>
      <Route path="/" element={<Login/>} />
      <Route path="/login" element={<Login/>} />
      <Route path="/register" element={<Registration/>} />

      </Routes>
    </div>
  )
}

export default RouterComponent
