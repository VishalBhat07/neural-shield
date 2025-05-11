// src/App.jsx
import React, { useState, useEffect } from "react";
import Header from "./components/Header";
import DropZone from "./components/Dropzone";
import FileInfo from "./components/Fileinfo";
import FeatureSection from "./components/FeatureSection";
import Footer from "./components/Footer";
import FileAnimation from "./components/FileAnimation";
import "./App.css";

const App = () => {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [animation, setAnimation] = useState(null);

  // Handle file processing
  const handleFiles = (files) => {
    const file = files[0];
    setFile(file);

    // Simulate scanning process
    setScanning(true);
    setScanResult(null);

    setTimeout(() => {
      setScanning(false);
      // Example result - in a real app, this would be based on actual scanning
      setScanResult({
        clean: Math.random() > 0.3, // Randomly show clean or infected for demo
        threatName: Math.random() > 0.3 ? null : "Example.Malware.Gen",
      });
    }, 2000);
  };

  // Clear animation after it completes
  const handleAnimationEnd = () => {
    setAnimation(null);
  };

  // Global drag and drop handling
  useEffect(() => {
    const handleGlobalDrop = (e) => {
      e.preventDefault();
      e.stopPropagation();

      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        setAnimation({
          x: e.clientX,
          y: e.clientY,
        });

        handleFiles(e.dataTransfer.files);
      }

      setDragActive(false);
    };

    const handleGlobalDragOver = (e) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(true);
    };

    const handleGlobalDragLeave = (e) => {
      if (
        e.clientX <= 0 ||
        e.clientY <= 0 ||
        e.clientX >= window.innerWidth ||
        e.clientY >= window.innerHeight
      ) {
        setDragActive(false);
      }
    };

    window.addEventListener("drop", handleGlobalDrop);
    window.addEventListener("dragover", handleGlobalDragOver);
    window.addEventListener("dragleave", handleGlobalDragLeave);

    return () => {
      window.removeEventListener("drop", handleGlobalDrop);
      window.removeEventListener("dragover", handleGlobalDragOver);
      window.removeEventListener("dragleave", handleGlobalDragLeave);
    };
  }, []);

  return (
    <div className="container">
      <Header />

      <main className="main">
        <DropZone
          handleFiles={handleFiles}
          dragActive={dragActive}
          setDragActive={setDragActive}
        />

        {(scanning || (file && scanResult)) && (
          <FileInfo file={file} scanning={scanning} scanResult={scanResult} />
        )}

        <FeatureSection />

        {animation && (
          <FileAnimation
            x={animation.x}
            y={animation.y}
            onAnimationEnd={handleAnimationEnd}
          />
        )}
      </main>

      <Footer />
    </div>
  );
};

export default App;
