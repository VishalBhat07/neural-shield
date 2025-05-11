import React, { useState, useRef, useEffect } from "react";
import { Shield, FileCheck, Upload, Github, AlertTriangle } from "lucide-react";

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
    maxWidth: "600px",
    display: "flex",
    alignItems: "center",
    gap: "15px",
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
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [animation, setAnimation] = useState(null);
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

    // Simulate scanning process
    setScanning(true);
    setScanResult(null);

    setTimeout(() => {
      setScanning(false);
      // Example result - in a real app, this would be based on actual scanning
      setScanResult({
        clean: Math.random() > 0.3, // Randomly show clean or infected for demo
        threatName: !this?.clean ? "Example.Malware.Gen" : null,
      });
    }, 2000);
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
              backgroundColor: scanResult.clean ? "#e6f7ee" : "#fde8e8",
              borderLeft: `5px solid ${
                scanResult.clean ? "#27ae60" : "#e74c3c"
              }`,
            }}
          >
            {scanResult.clean ? (
              <FileCheck size={24} color="#27ae60" />
            ) : (
              <AlertTriangle size={24} color="#e74c3c" />
            )}
            <div>
              <p style={{ fontWeight: "bold" }}>{file.name}</p>
              <p>
                {scanResult.clean
                  ? "File is clean and safe to use!"
                  : `Threat detected: ${scanResult.threatName}`}
              </p>
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
    </div>
  );
};

export default MalwareDetectionSystem;
