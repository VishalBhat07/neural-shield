// src/App.jsx
import React, { useState, useEffect } from "react";
import Header from "./components/Header";
import DropZone from "./components/DropZone";
import FileInfo from "./components/FileInfo";
import FeatureSection from "./components/FeatureSection";
import Footer from "./components/Footer";
import FileAnimation from "./components/FileAnimation";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
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
        score:
          result.probability !== undefined
            ? Math.round(result.probability * 100)
            : undefined,
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

    // Branding + color theme
    const colors = {
      bgPrimary: "#ffffff",
      bgSecondary: "#f9f9f9",
      bgTertiary: "#eeeeee",
      textPrimary: "#1a1a1a",
      textSecondary: "#666666",
      accentPrimary: "#5d5afa",
      accentSecondary: "#7b79fb",
      success: "#3ece6e",
      warning: "#f0b429",
      danger: "#f85149",
    };

    const hexToRgb = (hex) => {
      if (hex.length > 7) hex = hex.substring(0, 7);
      hex = hex.replace("#", "");
      const r = parseInt(hex.substring(0, 2), 16);
      const g = parseInt(hex.substring(2, 4), 16);
      const b = parseInt(hex.substring(4, 6), 16);
      return [r, g, b];
    };

    const formatFileSize = (bytes) => {
      if (bytes === 0) return "0 Bytes";
      const k = 1024;
      const sizes = ["Bytes", "KB", "MB", "GB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    };

    // Set fonts
    const setHeadingStyle = (size = 16) => {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(size);
      doc.setTextColor(...hexToRgb(colors.accentPrimary));
    };

    const setBodyStyle = (size = 10) => {
      doc.setFont("helvetica", "normal");
      doc.setFontSize(size);
      doc.setTextColor(...hexToRgb(colors.textPrimary));
    };

    const setSecondaryStyle = (size = 9) => {
      doc.setFont("helvetica", "normal");
      doc.setFontSize(size);
      doc.setTextColor(...hexToRgb(colors.textSecondary));
    };

    // Page setup
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    let y = margin;

    // Header branding
    doc.setFillColor(...hexToRgb(colors.bgSecondary));
    doc.rect(0, 0, pageWidth, 40, "F");

    setHeadingStyle(22);
    doc.setTextColor(...hexToRgb(colors.accentPrimary));
    doc.text("NeuralShield", margin, 20);

    setSecondaryStyle(11);
    doc.setTextColor(...hexToRgb(colors.accentSecondary));
    doc.text("Advanced Malware Detection", margin, 30);

    // Divider line
    doc.setDrawColor(...hexToRgb(colors.accentPrimary));
    doc.setLineWidth(1);
    doc.line(margin, 45, pageWidth - margin, 45);

    y = 55;

    // Title and date
    setHeadingStyle(16);
    doc.text("Malware Scan Report", pageWidth / 2, y, { align: "center" });

    setSecondaryStyle(10);
    doc.text(
      `Generated on ${new Date().toLocaleString()}`,
      pageWidth / 2,
      y + 8,
      { align: "center" }
    );

    y += 20;

    // Status card
    const isClean = !scanResult.malware_prediction;
    const statusColor = isClean ? colors.success : colors.danger;
    const statusText = isClean ? "CLEAN FILE" : "MALWARE DETECTED";
    const confidence = scanResult.probability
      ? Math.round(scanResult.probability * 100)
      : "N/A";

    doc.setFillColor(...hexToRgb("#f2f2f2"));
    doc.roundedRect(margin, y, pageWidth - margin * 2, 30, 3, 3, "F");

    doc.setFillColor(...hexToRgb(statusColor));
    doc.rect(margin, y, 4, 30, "F");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.setTextColor(...hexToRgb(statusColor));
    doc.text(statusText, margin + 10, y + 12);

    setBodyStyle();
    doc.text(`Confidence Score: ${confidence}%`, margin + 10, y + 22);

    y += 40;

    // File Information
    setHeadingStyle(14);
    doc.text("File Information", margin, y);

    y += 6;
    doc.setDrawColor(...hexToRgb(colors.bgTertiary));
    doc.setLineWidth(0.5);
    doc.line(margin, y, pageWidth - margin, y);
    y += 10;

    const fileData = [
      ["File Name", scanResult.file_name || "N/A"],
      [
        "File Size",
        scanResult.file_size ? formatFileSize(scanResult.file_size) : "N/A",
      ],
      ["Scan Date", new Date().toLocaleString()],
      [
        "Processing Time",
        typeof scanResult.processing_time === "number"
          ? `${scanResult.processing_time.toFixed(2)} s`
          : "N/A",
      ],
      [
        "Prediction Class",
        scanResult.prediction_class === 0 ? "Benign" : "Malware",
      ],
    ];

    autoTable(doc, {
      startY: y,
      body: fileData,
      theme: "plain",
      styles: {
        fontSize: 10,
        cellPadding: 4,
        textColor: hexToRgb(colors.textPrimary),
      },
      columnStyles: {
        0: {
          fontStyle: "bold",
          textColor: hexToRgb(colors.accentPrimary),
          cellWidth: 60,
        },
      },
      alternateRowStyles: {
        fillColor: hexToRgb(colors.bgSecondary),
      },
      margin: { left: margin, right: margin },
    });

    y = doc.lastAutoTable.finalY + 15;

    // Features Analyzed
    setHeadingStyle(14);
    doc.text("Features Analyzed", margin, y);

    y += 6;
    doc.setDrawColor(...hexToRgb(colors.bgTertiary));
    doc.line(margin, y, pageWidth - margin, y);

    y += 10;

    setSecondaryStyle();
    doc.text(
      "The following features were analyzed to determine the file's classification:",
      margin,
      y
    );

    y += 10;

    if (scanResult.feature_list && scanResult.features_used) {
      const featureData = scanResult.feature_list.map((feature, index) => [
        feature,
        String(scanResult.features_used[index]),
      ]);

      autoTable(doc, {
        startY: y,
        head: [["Feature", "Value"]],
        body: featureData,
        theme: "grid",
        headStyles: {
          fillColor: hexToRgb(colors.accentPrimary),
          textColor: 255,
          fontStyle: "bold",
        },
        styles: {
          fontSize: 9,
          textColor: hexToRgb(colors.textPrimary),
        },
        alternateRowStyles: {
          fillColor: hexToRgb(colors.bgSecondary),
        },
        margin: { left: margin, right: margin },
      });

      y = doc.lastAutoTable.finalY + 15;
    }

    // Recommendation
    setHeadingStyle(14);
    doc.text("Recommendation", margin, y);

    y += 6;
    doc.setDrawColor(...hexToRgb(colors.bgTertiary));
    doc.line(margin, y, pageWidth - margin, y);

    y += 10;

    doc.setFillColor(...hexToRgb(isClean ? colors.success : colors.danger));
    doc.roundedRect(margin, y, pageWidth - margin * 2, 25, 3, 3, "F");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.setTextColor(255, 255, 255);
    doc.text(
      isClean ? "File is Safe to Use" : "Security Risk Detected",
      margin + 10,
      y + 10
    );

    setBodyStyle();
    doc.setTextColor(255, 255, 255);
    doc.text(
      isClean
        ? "This file is classified as clean. No malicious patterns were detected."
        : "Malicious patterns were detected. We recommend deleting this file immediately.",
      margin + 10,
      y + 18,
      { maxWidth: pageWidth - margin * 2 - 10 }
    );

    // Footer
    const totalPages = doc.internal.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(...hexToRgb(colors.textSecondary));
      doc.text(
        `Generated by NeuralShield • ${new Date().toLocaleDateString()}`,
        pageWidth / 2,
        pageHeight - 10,
        { align: "center" }
      );
      doc.text(
        `Page ${i} of ${totalPages}`,
        pageWidth - margin,
        pageHeight - 10
      );
    }

    doc.save(`NeuralShield-report-${scanResult.file_name}.pdf`);
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
