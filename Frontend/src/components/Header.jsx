// src/components/Header.jsx
import React from 'react';
import { Shield } from 'lucide-react';

const Header = () => {
  return (
    <header className="header">
      <div className="header-content">
        <Shield size={32} />
        <h1>SecureShield</h1>
      </div>
      <p className="header-subtitle">Advanced File Malware Detection System</p>
    </header>
  );
};

export default Header;