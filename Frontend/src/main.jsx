import React, { createElement } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, HashRouter } from 'react-router-dom';
import App from './App.jsx';
import ThemeProvider from './context/ThemeProvider';
import ToastProvider from './context/ToastProvider';
import ConfirmProvider from './context/ConfirmProvider';
import AuthProvider from './context/AuthProvider';
import PolicyProvider from './context/PolicyProvider';
import { IS_PREVIEW } from './config';
import { initMotion } from './lib/motion';
import './styles/index.css';

initMotion();

// GitHub Pages cannot rewrite deep links, so the static Live preview uses hash routing (works under any sub-path).
const routerType = IS_PREVIEW ? HashRouter : BrowserRouter;

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider>
      <ToastProvider>
        <ConfirmProvider>
          {createElement(routerType, null, (
            <AuthProvider>
              <PolicyProvider>
                <App />
              </PolicyProvider>
            </AuthProvider>
          ))}
        </ConfirmProvider>
      </ToastProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
