// src/App.jsx
import React, { useState, useEffect } from "react";
import Header from "./components/Header";
import DropZone from "./components/DropZone";
import FileInfo from "./components/Fileinfo";
import FeatureSection from "./components/FeatureSection";
import Footer from "./components/Footer";
import FileAnimation from "./components/FileAnimation";
import jsPDF from "jspdf";
import "./App.css";

const App = () => {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [animation, setAnimation] = useState(null);
  const backendUrl = import.meta.env.VITE_BACKEND_URL;

  // Handle file processing
  const handleFiles = async (files) => {
    setFile(files);

    setScanning(true);
    setScanResult(null);

    if (!files || files.length === 0) return;

    const formData = new FormData();
    formData.append("file", files[0]); // For single file

    try {
      const response = await fetch(backendUrl + "/upload", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      console.log("Backend response:", result);

      // Set scanResult here so FileInfo can display it
      setScanning(false);
      setScanResult({
        ...result,
        clean: !result.malware_prediction,
        threatName: result.malware_prediction ? "Malware Detected" : null,
        score: result.probability !== undefined ? Math.round(result.probability * 100) : undefined,
      });
    } catch (error) {
      setScanning(false);
      setScanResult({
        clean: false,
        threatName: "Error scanning file",
        score: undefined,
      });
      console.error("Error uploading file:", error);
    }
  };

  // Generate report
  const generateReport = () => {
    if (!scanResult) return;

    const doc = new jsPDF();

    doc.setFontSize(16);
    doc.text("===== Malware Detection Report =====", 10, 15);

    doc.setFontSize(12);
    let y = 30;
    doc.text(`File: ${scanResult.file_name}`, 10, y);
    y += 8;
    doc.text(`Size: ${scanResult.file_size} bytes`, 10, y);
    y += 8;
    doc.text(`Scan Date: ${new Date().toLocaleString()}`, 10, y);
    y += 12;
    doc.text(`Result: ${scanResult.malware_prediction ? 'MALWARE DETECTED' : 'CLEAN'}`, 10, y);
    y += 8;
    doc.text(`Confidence: ${Math.round(scanResult.probability * 100)}%`, 10, y);
    y += 8;
    doc.text(`Prediction Class: ${scanResult.prediction_class} [0 for benign and 1 for malware]`, 10, y);
    y += 8;
    doc.text(`Processing Time: ${scanResult.processing_time.toFixed(2)}s`, 10, y);
    y += 12;

    doc.text("===== Features Analyzed =====", 10, y);
    y += 8;
    if (scanResult.feature_list && scanResult.features_used) {
      for (let i = 0; i < scanResult.feature_list.length; i++) {
        doc.text(`${scanResult.feature_list[i]}: ${scanResult.features_used[i]}`, 10, y);
        y += 7;
        if (y > 280) { // Avoid writing off the page
          doc.addPage();
          y = 15;
        }
      }
    }

    doc.save(`malware-report-${scanResult.file_name}.pdf`);
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
          <FileInfo
            file={file}
            scanning={scanning}
            scanResult={scanResult}
            generateReport={generateReport}
          />
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
