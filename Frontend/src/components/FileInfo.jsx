// src/components/FileInfo.jsx
import React from 'react';
import { FileCheck, AlertTriangle } from 'lucide-react';

const FileInfo = ({ file, scanning, scanResult }) => {
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
          <p className="file-name">{file.name}</p>
          <p className="scan-result">{scanResult.clean ? 
            'File is clean and safe to use!' : 
            `Threat detected: ${scanResult.threatName}`}
          </p>
        </div>
      </div>
    );
  }

  return null;
};

export default FileInfo;