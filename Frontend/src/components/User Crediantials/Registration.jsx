import { useState } from 'react';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const Registration = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [message, setMessage] = useState('');

    const handleRegister = async () => {
        try {
            if (password !== confirmPassword) {
                setMessage('Passwords do not match');
                return;
            }

            const response = await axios.post(`${API_URL}/auth/register`, {
                email,
                password
            });

            if (response.data.success) {
                setMessage('Registration successful');
                // Redirect to login page or handle success scenario
            } else {
                setMessage(response.data.message);
            }
        } catch (error) {
            console.error('Error during registration:', error.message);
            setMessage(error.response?.data?.message || 'An error occurred during registration');
        }
    };

    return (
        <div className="registration-container">
            <h2>Registration</h2>
            <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
            />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
            />
            <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
            />
            <button className="register-button" onClick={handleRegister}>
                Register
            </button>
            {message && <p>{message}</p>}
        </div>
    );
};

export default Registration;
