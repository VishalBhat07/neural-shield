// src/App.jsx
import React, { useState, useEffect } from "react";
import Header from "./components/Header";
import DropZone from "./components/DropZone";
import FileInfo from "./components/Fileinfo";
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
  // const generateReport = () => {
  //   if (!scanResult) return;

  //   const doc = new jsPDF();

  //   // Set font face to Helvetica for the whole document
  //   doc.setFont("helvetica", "normal");

  //   // Title
  //   doc.setFontSize(22);
  //   doc.setTextColor("#1976D2");
  //   doc.text(
  //     "Malware Detection Report by NeuralShield",
  //     105,
  //     20,
  //     null,
  //     null,
  //     "center"
  //   );

  //   // Draw a line under the title
  //   doc.setDrawColor(25, 118, 210);
  //   doc.setLineWidth(1);
  //   doc.line(20, 25, 190, 25);

  //   // Summary Table
  //   doc.setFontSize(12);
  //   doc.setTextColor("#000000");
  //   autoTable(doc, {
  //     startY: 30,
  //     head: [["Field", "Value"]],
  //     body: [
  //       ["File Name", scanResult.file_name || "N/A"],
  //       [
  //         "File Size",
  //         scanResult.file_size ? `${scanResult.file_size} bytes` : "N/A",
  //       ],
  //       ["Scan Date", new Date().toLocaleString()],
  //       [
  //         "Result",
  //         scanResult.malware_prediction ? "MALWARE DETECTED" : "CLEAN",
  //       ],
  //       [
  //         "Confidence",
  //         scanResult.probability !== undefined
  //           ? `${Math.round(scanResult.probability * 100)}%`
  //           : "N/A",
  //       ],
  //       [
  //         "Prediction Class",
  //         scanResult.prediction_class !== undefined
  //           ? scanResult.prediction_class == 0
  //             ? "Benign"
  //             : "Malware"
  //           : "N/A",
  //       ],
  //       [
  //         "Processing Time",
  //         typeof scanResult.processing_time === "number"
  //           ? `${scanResult.processing_time.toFixed(2)} s`
  //           : "N/A",
  //       ],
  //     ],
  //     theme: "striped",
  //     headStyles: {
  //       fillColor: [25, 118, 210],
  //       textColor: 255,
  //       fontStyle: "bold",
  //     },
  //     styles: { fontSize: 11, cellPadding: 3, font: "helvetica" },
  //     margin: { left: 20, right: 20 },
  //     tableLineColor: 200,
  //     tableLineWidth: 0.1,
  //   });

  //   // Features Table Section
  //   let y = doc.lastAutoTable.finalY + 10;
  //   doc.setFontSize(16);
  //   doc.setTextColor("#1976D2");
  //   doc.setFont("helvetica", "bold");
  //   doc.text("Features Analyzed", 105, y, null, null, "center");

  //   y += 5;

  //   autoTable(doc, {
  //     startY: y,
  //     head: [["Feature", "Value"]],
  //     body:
  //       Array.isArray(scanResult.feature_list) &&
  //       Array.isArray(scanResult.features_used)
  //         ? scanResult.feature_list.map((feature, index) => [
  //             feature,
  //             String(scanResult.features_used[index]),
  //           ])
  //         : [],
  //     theme: "grid",
  //     headStyles: {
  //       fillColor: [25, 118, 210],
  //       textColor: 255,
  //       fontStyle: "bold",
  //     },
  //     alternateRowStyles: { fillColor: [245, 245, 245] },
  //     styles: { fontSize: 10, font: "helvetica" },
  //     margin: { left: 20, right: 20 },
  //     tableLineColor: 200,
  //     tableLineWidth: 0.1,
  //   });

  //   // Footer
  //   const pageHeight = doc.internal.pageSize.height;
  //   doc.setFontSize(10);
  //   doc.setTextColor("#888");
  //   doc.setFont("helvetica", "normal");
  //   doc.text(
  //     `Generated by File Malware Detection System NeuralShield • ${new Date().toLocaleString()}`,
  //     105,
  //     pageHeight - 10,
  //     null,
  //     null,
  //     "center"
  //   );

  //   doc.save(`NeuralShield-report-${scanResult.file_name}.pdf`);
  // };

  // Generate report
  const generateReport = () => {
    if (!scanResult) return;

    const doc = new jsPDF();

    // Set font face to Helvetica for the whole document
    doc.setFont("helvetica", "normal");

    // Title
    doc.setFontSize(22);
    doc.setTextColor(93, 90, 250); // --accent-primary
    doc.text(
      "Malware Detection Report by NeuralShield",
      105,
      20,
      null,
      null,
      "center"
    );

    // Draw a line under the title
    doc.setDrawColor(93, 90, 250); // --accent-primary
    doc.setLineWidth(1);
    doc.line(20, 25, 190, 25);

    // Summary Table
    doc.setFontSize(12);
    doc.setTextColor(240, 246, 252); // --text-primary
    autoTable(doc, {
      startY: 30,
      head: [["Field", "Value"]],
      body: [
        ["File Name", scanResult.file_name || "N/A"],
        [
          "File Size",
          scanResult.file_size ? `${scanResult.file_size} bytes` : "N/A",
        ],
        ["Scan Date", new Date().toLocaleString()],
        [
          "Result",
          scanResult.malware_prediction ? "MALWARE DETECTED" : "CLEAN",
        ],
        [
          "Confidence",
          scanResult.probability !== undefined
            ? `${Math.round(scanResult.probability * 100)}%`
            : "N/A",
        ],
        [
          "Prediction Class",
          scanResult.prediction_class !== undefined
            ? scanResult.prediction_class == 0
              ? "Benign"
              : "Malware"
            : "N/A",
        ],
        [
          "Processing Time",
          typeof scanResult.processing_time === "number"
            ? `${scanResult.processing_time.toFixed(2)} s`
            : "N/A",
        ],
      ],
      theme: "striped",
      headStyles: {
        fillColor: [93, 90, 250], // --accent-primary
        textColor: 255,
        fontStyle: "bold",
      },
      styles: {
        fontSize: 11,
        cellPadding: 3,
        font: "helvetica",
        textColor: [240, 246, 252], // --text-primary
      },
      margin: { left: 20, right: 20 },
      tableLineColor: [48, 54, 61], // --border-color
      tableLineWidth: 0.1,
    });

    // Features Table Section
    let y = doc.lastAutoTable.finalY + 10;
    doc.setFontSize(16);
    doc.setTextColor(93, 90, 250); // --accent-primary
    doc.setFont("helvetica", "bold");
    doc.text("Features Analyzed", 105, y, null, null, "center");

    y += 5;

    autoTable(doc, {
      startY: y,
      head: [["Feature", "Value"]],
      body:
        Array.isArray(scanResult.feature_list) &&
        Array.isArray(scanResult.features_used)
          ? scanResult.feature_list.map((feature, index) => [
              feature,
              String(scanResult.features_used[index]),
            ])
          : [],
      theme: "grid",
      headStyles: {
        fillColor: [93, 90, 250], // --accent-primary
        textColor: 255,
        fontStyle: "bold",
      },
      alternateRowStyles: { fillColor: [33, 38, 45] }, // --bg-tertiary
      styles: {
        fontSize: 10,
        font: "helvetica",
        textColor: [240, 246, 252], // --text-primary
      },
      margin: { left: 20, right: 20 },
      tableLineColor: [48, 54, 61], // --border-color
      tableLineWidth: 0.1,
    });

    // Footer
    const pageHeight = doc.internal.pageSize.height;
    doc.setFontSize(10);
    doc.setTextColor(139, 148, 158); // --text-secondary
    doc.setFont("helvetica", "normal");
    doc.text(
      `Generated by File Malware Detection System NeuralShield • ${new Date().toLocaleString()}`,
      105,
      pageHeight - 10,
      null,
      null,
      "center"
    );

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
