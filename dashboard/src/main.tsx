import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource-variable/inter';
import App from './App';
import './index.css';

const rootEl = document.getElementById('root');
if (!rootEl) {
  throw new Error('MCPIP dashboard: #root mount node not found');
}

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

// Register the PWA service worker so the console is installable (add to home
// screen) and works offline as a shell. Production builds only — in dev the SW
// would shadow Vite's HMR. The worker never caches the gateway API (see sw.js),
// so the authorization path is always live; registration failure is non-fatal.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {
      /* installability is a progressive enhancement — never block the app. */
    });
  });
}
