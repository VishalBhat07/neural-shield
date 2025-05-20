// src/components/FileInfo.jsx
import React, { useEffect } from 'react';
import { FileCheck, AlertTriangle } from 'lucide-react';

const FileInfo = ({ file, scanning, scanResult, generateReport }) => {
  useEffect(() => {
    console.log("scanResult updated:", scanResult);
  }, [scanResult]);

  if (!file) return null;

  if (scanning) {
    return (
      <div className="file-info">
        <div className="file-info-content">
          <div className="spinner"></div>
          <p>Scanning {file.name}...</p>
        </div>
      </div>
    );
  }

  if (scanResult) {
    return (
      <div className={`file-info ${scanResult.clean ? 'file-clean' : 'file-infected'}`}>
        {scanResult.clean ? (
          <FileCheck size={24} className="result-icon clean" />
        ) : (
          <AlertTriangle size={24} className="result-icon infected" />
        )}
        <div className="file-details">
          <div>
            <p style={{ fontWeight: "bold" }}>{file.name}</p>
            <p>
              {scanResult.clean
                ? "File is clean and safe to use!"
                : `Threat detected: ${scanResult.threatName}`}
            </p>
            {scanResult.score !== undefined && (
              <p>
                Model confidence: <b>{scanResult.score}%</b>
              </p>
            )}
            {/* Additional info */}
            {scanResult.file_name && (
              <p>
                <b>File name:</b> {scanResult.file_name}
              </p>
            )}
            {scanResult.file_size !== undefined && (
              <p>
                <b>File size:</b> {scanResult.file_size} bytes
              </p>
            )}
            {scanResult.prediction_class !== undefined && (
              <p>
                <b>Prediction class:</b> {scanResult.prediction_class} <b>(0 - Benign | 1 - malware)</b>
              </p>
            )}
            {scanResult.processing_time !== undefined && (
              <p>
                <b>Processing time:</b> {scanResult.processing_time.toFixed(3)} seconds
              </p>
            )}
          </div>
          <button onClick={generateReport}>Export Report</button>
        </div>
      </div>
    );
  }

  return null;
};

export default FileInfo;