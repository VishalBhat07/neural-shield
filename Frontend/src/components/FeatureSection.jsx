// src/components/FeatureSection.jsx
import React from "react";
import { Shield, Zap, Lock, Database, Clock, Globe } from "lucide-react";

const FeatureSection = () => {
  const features = [
    {
      icon: <Shield size={24} />,
      title: "Advanced Threat Detection",
      description:
        "Utilizes cutting-edge machine learning algorithms to detect even the most sophisticated malware variants",
    },
    {
      icon: <Zap size={24} />,
      title: "Real-time Scanning",
      description:
        "Ultra-fast scanning engine processes files in seconds with minimal system impact",
    },
    {
      icon: <Lock size={24} />,
      title: "Privacy First",
      description:
        "Your files never leave your device - all scanning is performed locally for maximum privacy",
    },
    {
      icon: <Database size={24} />,
      title: "Comprehensive Database",
      description:
        "Regularly updated threat database with signatures for over 20 million known malware variants",
    },
    {
      icon: <Clock size={24} />,
      title: "Daily Updates",
      description:
        "Protection against zero-day threats with daily definition updates",
    },
    {
      icon: <Globe size={24} />,
      title: "Open Source",
      description:
        "Community-driven, transparent codebase that security researchers can audit and improve",
    },
  ];

  return (
    <section className="features-section">
      <h2 className="features-title">Key Features</h2>
      <div className="features-grid">
        {features.map((feature, index) => (
          <div className="feature-card" key={index}>
            <div className="feature-icon">{feature.icon}</div>
            <h3 className="feature-title">{feature.title}</h3>
            <p className="feature-description">{feature.description}</p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default FeatureSection;
