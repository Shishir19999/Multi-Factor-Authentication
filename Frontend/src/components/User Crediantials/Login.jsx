import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { setToken } from '../../auth/auth';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const errMessage = (error, fallback) => error.response?.data?.message || fallback;

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [otp, setOtp] = useState('');
    const [showOtpField, setShowOtpField] = useState(false);
    const [cooldown, setCooldown] = useState(0);
    const [info, setInfo] = useState('');
    const navigate = useNavigate();

    // Countdown for the resend button
    useEffect(() => {
        if (cooldown <= 0) return undefined;
        const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
        return () => clearTimeout(t);
    }, [cooldown]);

    const handleLogin = async () => {
        setInfo('');
        try {
            const response = await axios.post(`${API_URL}/auth/login`, { email, password });

            if (response.data.success) {
                setShowOtpField(true);
                setOtp('');
                setCooldown(response.data.resendCooldownSeconds || 30);
                setInfo('OTP sent to your email. Check your inbox.');
            } else {
                setInfo(response.data.message);
            }
        } catch (error) {
            console.error('Error during login:', error.message);
            setInfo(errMessage(error, 'An error occurred during login'));
        }
    };

    const handleResend = async () => {
        setInfo('');
        try {
            const response = await axios.post(`${API_URL}/auth/resend-otp`, { email });
            if (response.data.success) {
                setCooldown(response.data.resendCooldownSeconds || 30);
                setInfo('A new code has been sent.');
            }
        } catch (error) {
            const wait = error.response?.data?.retryAfterSeconds;
            if (wait) setCooldown(wait);
            setInfo(errMessage(error, 'Could not resend the code'));
        }
    };

    const handleOtpVerification = async () => {
        setInfo('');
        try {
            const otpResponse = await axios.post(`${API_URL}/auth/verify-otp`, { email, otp });

            if (otpResponse.data.success) {
                setToken(otpResponse.data.token);
                navigate('/dashboard', { replace: true });
            } else {
                setInfo(otpResponse.data.message || 'Invalid OTP. Please try again.');
            }
        } catch (error) {
            console.error('Error during OTP verification:', error.message);
            setInfo(errMessage(error, 'An error occurred during OTP verification'));
        }
    };

    return (
        <div className="login-container">
            <input type="email"
                placeholder="Email"
                onChange={(e) => setEmail(e.target.value)} />
            <input type="password"
                placeholder="Password"
                onChange={(e) => setPassword(e.target.value)} />

            {showOtpField && (
                <>
                    <input type="text"
                        placeholder="OTP"
                        inputMode="numeric"
                        maxLength={6}
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)} />
                    <button className="login-button"
                        onClick={handleOtpVerification}>
                        Verify OTP
                    </button>
                    <button className="login-button"
                        onClick={handleResend}
                        disabled={cooldown > 0}>
                        {cooldown > 0 ? `Resend code (${cooldown}s)` : 'Resend code'}
                    </button>
                </>
            )}

            <button className="login-button"
                onClick={handleLogin}>
                Login
            </button>
            {info && <p role="status">{info}</p>}
        </div>
    );
};

export default Login;
