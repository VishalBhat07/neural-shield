// src/components/Footer.jsx
import React from "react";
import { Github, Twitter, Mail, Phone } from "lucide-react";

const Footer = () => {
  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-section">
          <h3>NeuralShield</h3>
          <p>
            An open-source file malware detection system designed to keep your
            data safe.
          </p>
          <p>Designed by Vishal K Bhat, Sumedh Udupa U, V S Sreenvivaas</p>
        </div>

        <div className="footer-section">
          <h3>Quick Links</h3>
          <ul className="footer-links">
            <li>
              <a href="#">Documentation</a>
            </li>
            <li>
              <a href="#">API</a>
            </li>
            <li>
              <a href="#">Contributing</a>
            </li>
            <li>
              <a href="#">Report Issues</a>
            </li>
          </ul>
        </div>

        <div className="footer-section">
          <h3>Connect</h3>
          <div className="social-links">
            <a
              href="https://github.com/vishalbhat07/neural-shield"
              target="_blank"
              rel="noopener noreferrer"
              className="social-link"
            >
              <Github size={20} />
              <span>GitHub</span>
            </a>
            <a
              href="mailto:vishalkbhat.cs23@rvce.edu.in"
              className="social-link"
            >
              <Mail size={20} />
              <span>Email</span>
            </a>
            <a href="#" className="social-link">
              <Phone size={20} />
              <span>+91 7975806665</span>
            </a>
          </div>
        </div>
      </div>

      <div className="footer-bottom">
        <p>
          &copy; {new Date().getFullYear()} Neural Shield. All rights reserved.
        </p>
      </div>
    </footer>
  );
};

export default Footer;
