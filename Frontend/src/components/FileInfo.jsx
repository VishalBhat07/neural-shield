// src/components/FileInfo.jsx
import React, { useEffect } from "react";
import {
  FileCheck,
  AlertTriangle,
  FileText,
  Clock,
  Database,
  Cpu,
  Download,
} from "lucide-react";

const FileInfo = ({ file, scanning, scanResult, generateReport }) => {
  useEffect(() => {
    console.log("scanResult updated:", scanResult);
  }, [scanResult]);

  if (!file) return null;

  if (scanning) {
    return (
      <div className="file-info-container">
        <div className="file-info-card scanning">
          <div className="file-info-header">
            <h2>Scanning File</h2>
          </div>
          <div className="file-info-body">
            <div className="scanning-animation">
              <div className="spinner-large"></div>
            </div>
            <div className="scanning-details">
              <h3>Analyzing {file[0]?.name}</h3>
              <p>
                Our advanced neural network is examining your file for potential
                threats...
              </p>
              <div className="scan-progress">
                <div className="scan-progress-bar"></div>
              </div>
              <ul className="scanning-steps">
                <li className="completed">File received</li>
                <li className="active">Feature extraction</li>
                <li>Neural network analysis</li>
                <li>Generating report</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (scanResult) {
    // Determine status for styling
    const isClean = scanResult.clean;
    const statusClass = isClean ? "clean" : "infected";

    // Features section - only show if we have data
    const hasFeatures =
      Array.isArray(scanResult.feature_list) &&
      Array.isArray(scanResult.features_used) &&
      scanResult.feature_list.length > 0;

    return (
      <div className="file-info-container">
        <div className={`file-info-card ${statusClass}`}>
          {/* Results Header */}
          <div className="file-info-header">
            <div className={`status-indicator ${statusClass}`}>
              {isClean ? (
                <FileCheck size={28} className="status-icon" />
              ) : (
                <AlertTriangle size={28} className="status-icon" />
              )}
              <h2>{isClean ? "File is Safe" : "Threat Detected"}</h2>
            </div>
            <button onClick={generateReport} className="export-button">
              <Download size={16} />
              Export PDF Report
            </button>
          </div>

          {/* Main Results Section */}
          <div className="file-info-body">
            {/* Score Card */}
            <div className="result-score-card">
              <div className={`score-ring ${statusClass}`}>
                <div className="score-value">
                  {scanResult.score !== undefined ? (
                    <span>
                      {scanResult.score}
                      <small>%</small>
                    </span>
                  ) : (
                    <span>N/A</span>
                  )}
                </div>
              </div>
              <div className="score-details">
                <h3>{isClean ? "Confidence: Clean" : "Threat Level"}</h3>
                <p>
                  {isClean
                    ? "Our AI model has determined this file is safe to use"
                    : scanResult.threatName || "Unknown threat detected"}
                </p>
              </div>
            </div>

            {/* File Details Section */}
            <div className="details-grid">
              <div className="detail-card">
                <div className="detail-icon">
                  <FileText size={18} />
                </div>
                <div className="detail-info">
                  <h4>File Name</h4>
                  <p>
                    {scanResult.file_name || file[0]?.name || "Unknown file"}
                  </p>
                </div>
              </div>

              <div className="detail-card">
                <div className="detail-icon">
                  <Database size={18} />
                </div>
                <div className="detail-info">
                  <h4>File Size</h4>
                  <p>
                    {scanResult.file_size !== undefined
                      ? formatFileSize(scanResult.file_size)
                      : "Unknown size"}
                  </p>
                </div>
              </div>

              <div className="detail-card">
                <div className="detail-icon">
                  <Cpu size={18} />
                </div>
                <div className="detail-info">
                  <h4>Prediction Class</h4>
                  <p>
                    {scanResult.prediction_class !== undefined
                      ? scanResult.prediction_class === 0
                        ? "Benign (0)"
                        : "Malware (1)"
                      : "Unknown"}
                  </p>
                </div>
              </div>

              <div className="detail-card">
                <div className="detail-icon">
                  <Clock size={18} />
                </div>
                <div className="detail-info">
                  <h4>Processing Time</h4>
                  <p>
                    {scanResult.processing_time !== undefined
                      ? `${scanResult.processing_time.toFixed(2)} seconds`
                      : "Not available"}
                  </p>
                </div>
              </div>
            </div>

            {/* Feature Analysis Section */}
            {hasFeatures && (
              <div className="features-analysis">
                <h3>Feature Analysis</h3>
                <p className="features-description">
                  Our neural network analyzed the following key features to
                  determine malware probability:
                </p>

                <div className="features-table-container">
                  <table className="features-table">
                    <thead>
                      <tr>
                        <th>Feature Name</th>
                        <th>Value</th>
                        <th>Impact</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResult.feature_list.map((feature, index) => {
                        // Feature impact based on value (simplified)
                        const value = scanResult.features_used[index];
                        let impact = "neutral";

                        // Just a heuristic for visualization - adapt as needed
                        if (typeof value === "number") {
                          if (
                            (scanResult.prediction_class === 1 &&
                              value > 0.6) ||
                            (scanResult.prediction_class === 0 && value < 0.4)
                          ) {
                            impact = "negative";
                          } else if (
                            (scanResult.prediction_class === 1 &&
                              value < 0.4) ||
                            (scanResult.prediction_class === 0 && value > 0.6)
                          ) {
                            impact = "positive";
                          }
                        }

                        return (
                          <tr key={index}>
                            <td>{feature}</td>
                            <td>
                              {typeof value === "number"
                                ? value.toFixed(4)
                                : String(value)}
                            </td>
                            <td>
                              <div
                                className={`impact-indicator ${impact}`}
                              ></div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Recommendation Section */}
            <div className={`recommendation ${statusClass}`}>
              <h3>Recommendation</h3>
              {isClean ? (
                <p>
                  This file appears to be safe based on our AI analysis. You can
                  proceed with using it.
                </p>
              ) : (
                <p>
                  This file has been identified as potentially malicious. We
                  recommend against opening or executing it.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return null;
};

// Helper function to format file size
function formatFileSize(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export default FileInfo;
