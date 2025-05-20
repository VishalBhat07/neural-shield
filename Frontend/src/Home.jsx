import React, { useState, useRef, useEffect } from "react";
import { Shield, FileCheck, Upload, Github, AlertTriangle, ChevronDown, ChevronUp, Download } from "lucide-react";
//useless file as it is not used in the code
// CSS styles
const styles = {
  container: {
    display: "flex",
    flexDirection: "column",
    minHeight: "100vh",
    fontFamily: "Arial, sans-serif",
    color: "#333",
    backgroundColor: "#f5f5f5",
  },
  header: {
    backgroundColor: "#2c3e50",
    color: "white",
    padding: "20px",
    textAlign: "center",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    gap: "15px",
  },
  main: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    padding: "40px 20px",
  },
  dropZone: {
    width: "80%",
    maxWidth: "600px",
    padding: "40px",
    border: "3px dashed #2c3e50",
    borderRadius: "12px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    textAlign: "center",
    cursor: "pointer",
    transition: "all 0.3s ease",
    backgroundColor: "white",
    position: "relative",
    overflow: "hidden",
  },
  dragActive: {
    borderColor: "#27ae60",
    backgroundColor: "rgba(39, 174, 96, 0.1)",
    transform: "scale(1.02)",
  },
  fileInput: {
    opacity: 0,
    position: "absolute",
    top: 0,
    left: 0,
    width: "100%",
    height: "100%",
    cursor: "pointer",
  },
  uploadIcon: {
    marginBottom: "15px",
  },
  uploadText: {
    fontSize: "18px",
    marginBottom: "10px",
  },
  uploadSubtext: {
    fontSize: "14px",
    color: "#7f8c8d",
    marginBottom: "20px",
  },
  browseButton: {
    backgroundColor: "#2c3e50",
    color: "white",
    border: "none",
    padding: "10px 20px",
    borderRadius: "4px",
    fontSize: "16px",
    cursor: "pointer",
    transition: "background-color 0.3s ease",
  },
  fileInfo: {
    marginTop: "30px",
    padding: "20px",
    backgroundColor: "white",
    borderRadius: "8px",
    boxShadow: "0 2px 10px rgba(0, 0, 0, 0.1)",
    width: "80%",
    maxWidth: "800px",
    display: "flex",
    flexDirection: "column",
  },
  resultHeader: {
    display: "flex",
    alignItems: "center",
    gap: "15px",
    marginBottom: "15px",
  },
  detailSection: {
    marginTop: "15px",
    borderTop: "1px solid #eee",
    paddingTop: "15px",
  },
  detailToggle: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    background: "none",
    border: "none",
    padding: "10px 0",
    width: "100%",
    cursor: "pointer",
    fontWeight: "bold",
  },
  featureGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
    gap: "10px",
    marginTop: "10px",
  },
  featureItem: {
    padding: "8px",
    backgroundColor: "#f0f0f0",
    borderRadius: "4px",
    fontSize: "13px",
  },
  progressBar: {
    height: "8px",
    backgroundColor: "#e0e0e0",
    borderRadius: "4px",
    overflow: "hidden",
    marginTop: "5px",
    width: "100%",
  },
  progressFill: {
    height: "100%",
    backgroundColor: "#e74c3c",
    transition: "width 0.5s ease",
  },
  footer: {
    backgroundColor: "#2c3e50",
    color: "white",
    padding: "20px",
    textAlign: "center",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    gap: "10px",
  },
  githubLink: {
    color: "white",
    textDecoration: "none",
    display: "flex",
    alignItems: "center",
    gap: "5px",
    transition: "opacity 0.3s ease",
  },
  fileAnimation: {
    position: "absolute",
    borderRadius: "50%",
    backgroundColor: "rgba(39, 174, 96, 0.5)",
    pointerEvents: "none",
    animation: "dropAnimation 0.8s ease-out",
    zIndex: 10,
  },
  badge: {
    display: "inline-block",
    padding: "4px 8px",
    borderRadius: "4px",
    fontSize: "12px",
    fontWeight: "bold",
    color: "white",
    marginLeft: "10px",
  },
  threatBadge: {
    backgroundColor: "#e74c3c",
  },
  safeBadge: {
    backgroundColor: "#27ae60",
  },
  detailGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(2, 1fr)",
    gap: "10px",
    marginTop: "10px",
  },
  detailItem: {
    padding: "10px",
    backgroundColor: "#f0f0f0",
    borderRadius: "4px",
    display: "flex",
    flexDirection: "column",
  },
  detailLabel: {
    fontSize: "12px",
    color: "#7f8c8d",
    marginBottom: "2px",
  },
  detailValue: {
    fontWeight: "bold",
  },
  reportButton: {
    display: "flex",
    alignItems: "center",
    gap: "5px",
    backgroundColor: "#3498db",
    color: "white",
    border: "none",
    padding: "8px 16px",
    borderRadius: "4px",
    cursor: "pointer",
    marginTop: "15px",
    alignSelf: "flex-end",
  },
  "@keyframes dropAnimation": {
    "0%": {
      transform: "scale(0)",
      opacity: 1,
    },
    "100%": {
      transform: "scale(5)",
      opacity: 0,
    },
  },
};

// File animation component
const FileAnimation = ({ x, y, onAnimationEnd }) => {
  const animationStyle = {
    left: `${x}px`,
    top: `${y}px`,
    position: "fixed",
    width: "20px",
    height: "20px",
    borderRadius: "50%",
    backgroundColor: "rgba(39, 174, 96, 0.5)",
    pointerEvents: "none",
    zIndex: 10,
    animation: "dropAnimation 0.8s ease-out forwards",
  };

  return <div style={animationStyle} onAnimationEnd={onAnimationEnd} />;
};

// Main component
const MalwareDetectionSystem = () => {
  console.log("MalwareDetectionSystem component rendered");

  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [animation, setAnimation] = useState(null);
  const [showFeatures, setShowFeatures] = useState(false);
  const [showDetails, setShowDetails] = useState(true);
  const fileInputRef = useRef(null);
  const dropZoneRef = useRef(null);

  // Handle drag events
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();

    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  // Handle drop event
  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    // Create animation from drop position to dropzone
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const dropZoneRect = dropZoneRef.current.getBoundingClientRect();
      const dropZoneCenterX = dropZoneRect.left + dropZoneRect.width / 2;
      const dropZoneCenterY = dropZoneRect.top + dropZoneRect.height / 2;

      setAnimation({
        x: e.clientX,
        y: e.clientY,
        targetX: dropZoneCenterX,
        targetY: dropZoneCenterY,
      });

      handleFiles(e.dataTransfer.files);
    }
  };

  // Handle file input change
  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFiles(e.target.files);
    }
  };

  // Process uploaded files
  const handleFiles = (files) => {
    const file = files[0];
    setFile(file);
    setScanning(true);
    setScanResult(null);

    // Prepare form data
    const formData = new FormData();
    formData.append("file", file);

    // Simulate API call for demonstration
    // In a real application, you would use the actual fetch call to your backend
    setTimeout(() => {
      // Mock response
      const mockResponse = {
        feature_list: ['MajorLinkerVersion', 'MinorOperatingSystemVersion', 'MajorSubsystemVersion', 'SizeOfStackReserve', 'TimeDateStamp', 'MajorOperatingSystemVersion', 'Characteristics', 'ImageBase', 'Subsystem', 'MinorImageVersion', 'MinorSubsystemVersion', 'SizeOfInitializedData', 'DllCharacteristics', 'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'CheckSum', 'DirectoryEntryImportSize', 'SectionMaxChar', 'MajorImageVersion', 'AddressOfEntryPoint', 'SectionMinEntropy', 'SizeOfHeaders', 'SectionMinVirtualsize'],
        features_used: [11, 0, 4, 1048576, 1381682754, 4, 258, 4194304, 2, 0, 0, 2048, 34112, 0, 0, 0, 87, 3, 0, 41454, 0.08153941234324169, 512, 12],
        file_name: file.name,
        file_size: file.size,
        malware_prediction: true,
        message: "File processed successfully",
        prediction_class: 1,
        probability: 0.91,
        processing_time: 0.5089
      };

      setScanning(false);
      setScanResult(mockResponse);
    }, 2000);

    // Actual backend call (commented out for now)
    /*
    fetch("http://localhost:8080/upload", {
      method: "POST",
      body: formData,
    })
      .then(async (res) => {
        const data = await res.json();
        setScanning(false);

        if (data.error) {
          setScanResult({
            clean: false,
            threatName: data.error,
            score: undefined,
          });
          return;
        }

        setScanResult(data);
      })
      .catch((err) => {
        setScanning(false);
        setScanResult({
          clean: false,
          threatName: "Error scanning file",
          score: undefined,
        });
      });
    */
  };

  // Handle click on dropzone
  const onButtonClick = () => {
    fileInputRef.current.click();
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
        const dropZoneRect = dropZoneRef.current.getBoundingClientRect();
        const dropZoneCenterX = dropZoneRect.left + dropZoneRect.width / 2;
        const dropZoneCenterY = dropZoneRect.top + dropZoneRect.height / 2;

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

  // Format bytes into human readable format
  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  // Generate scan report as text
  const generateReport = () => {
    if (!scanResult) return;

    let reportText = `===== Malware Detection Report =====\n\n`;
    reportText += `File: ${scanResult.file_name}\n`;
    reportText += `Size: ${formatBytes(scanResult.file_size)}\n`;
    reportText += `Scan Date: ${new Date().toLocaleString()}\n\n`;
    reportText += `Result: ${scanResult.malware_prediction ? 'MALWARE DETECTED' : 'CLEAN'}\n`;
    reportText += `Confidence: ${Math.round(scanResult.probability * 100)}%\n`;
    reportText += `Prediction Class: ${scanResult.prediction_class}\n`;
    reportText += `Processing Time: ${scanResult.processing_time.toFixed(2)}s\n\n`;
    
    reportText += `===== Features Analyzed =====\n\n`;
    if (scanResult.feature_list && scanResult.features_used) {
      for (let i = 0; i < scanResult.feature_list.length; i++) {
        reportText += `${scanResult.feature_list[i]}: ${scanResult.features_used[i]}\n`;
      }
    }

    // Create blob and download
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `malware-report-${scanResult.file_name}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <Shield size={32} />
        <h1>File Malware Detection System</h1>
      </header>

      <main style={styles.main}>
        <div
          ref={dropZoneRef}
          style={{
            ...styles.dropZone,
            ...(dragActive ? styles.dragActive : {}),
          }}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={onButtonClick}
        >
          <input
            ref={fileInputRef}
            style={styles.fileInput}
            type="file"
            onChange={handleChange}
          />
          <Upload size={48} style={styles.uploadIcon} />
          <p style={styles.uploadText}>Drag & drop your file here</p>
          <p style={styles.uploadSubtext}>or click to browse</p>
          <button style={styles.browseButton}>Select File</button>
        </div>

        {scanning && (
          <div style={styles.fileInfo}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <div
                style={{
                  width: "24px",
                  height: "24px",
                  border: "3px solid #3498db",
                  borderTopColor: "transparent",
                  borderRadius: "50%",
                  animation: "spin 1s linear infinite",
                }}
              />
              <p>Scanning {file?.name}...</p>
            </div>
            <style>
              {`
                @keyframes spin {
                  0% { transform: rotate(0deg); }
                  100% { transform: rotate(360deg); }
                }
              `}
            </style>
          </div>
        )}

        {!scanning && file && scanResult && (
          <div
            style={{
              ...styles.fileInfo,
              backgroundColor: !scanResult.malware_prediction ? "#e6f7ee" : "#fde8e8",
              borderLeft: `5px solid ${
                !scanResult.malware_prediction ? "#27ae60" : "#e74c3c"
              }`,
            }}
          >
            <div style={styles.resultHeader}>
              {!scanResult.malware_prediction ? (
                <FileCheck size={24} color="#27ae60" />
              ) : (
                <AlertTriangle size={24} color="#e74c3c" />
              )}
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center" }}>
                  <p style={{ fontWeight: "bold", margin: 0 }}>{scanResult.file_name}</p>
                  <span 
                    style={{
                      ...styles.badge, 
                      ...(scanResult.malware_prediction ? styles.threatBadge : styles.safeBadge)
                    }}
                  >
                    {scanResult.malware_prediction ? "MALWARE" : "CLEAN"}
                  </span>
                </div>
                <p style={{ margin: "5px 0 0" }}>
                  {scanResult.malware_prediction
                    ? "Malware detected! This file may be harmful to your system."
                    : "File is clean and safe to use!"}
                </p>
              </div>
              {console.log("Rendering report button", scanResult)}
              <button 
                style={styles.reportButton}
                onClick={generateReport}
              >
                <Download size={16} />
                Export Report
              </button>
            </div>

            {/* File Details Section */}
            <div style={styles.detailSection}>
              <button 
                style={styles.detailToggle}
                onClick={() => setShowDetails(!showDetails)}
              >
                <span>File Details</span>
                {showDetails ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
              </button>
              
              {showDetails && (
                <div style={styles.detailGrid}>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>File Size</span>
                    <span style={styles.detailValue}>{formatBytes(scanResult.file_size)}</span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Processing Time</span>
                    <span style={styles.detailValue}>{scanResult.processing_time.toFixed(2)}s</span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Confidence</span>
                    <span style={styles.detailValue}>{Math.round(scanResult.probability * 100)}%</span>
                    <div style={styles.progressBar}>
                      <div 
                        style={{
                          ...styles.progressFill,
                          width: `${scanResult.probability * 100}%`,
                          backgroundColor: scanResult.malware_prediction ? "#e74c3c" : "#27ae60"
                        }}
                      />
                    </div>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Prediction Class</span>
                    <span style={styles.detailValue}>{scanResult.prediction_class}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Features Section */}
            <div style={styles.detailSection}>
              <button 
                style={styles.detailToggle}
                onClick={() => setShowFeatures(!showFeatures)}
              >
                <span>Analysis Features ({scanResult.feature_list?.length || 0})</span>
                {showFeatures ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
              </button>
              
              {showFeatures && scanResult.feature_list && scanResult.features_used && (
                <div style={styles.featureGrid}>
                  {scanResult.feature_list.map((feature, index) => (
                    <div key={index} style={styles.featureItem}>
                      <strong>{feature}:</strong> {scanResult.features_used[index]}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {animation && (
          <FileAnimation
            x={animation.x}
            y={animation.y}
            onAnimationEnd={handleAnimationEnd}
          />
        )}
      </main>

      <footer style={styles.footer}>
        <p>© 2025 File Malware Detection System</p>
        <a
          href="https://github.com/username/malware-detection-system"
          target="_blank"
          rel="noopener noreferrer"
          style={styles.githubLink}
        >
          <Github size={18} />
          View on GitHub
        </a>
      </footer>
      {console.log("scanning:", scanning)}
      {console.log("file:", file)}
      {console.log("scanResult:", scanResult)}
    </div>
  );
};

export default MalwareDetectionSystem;