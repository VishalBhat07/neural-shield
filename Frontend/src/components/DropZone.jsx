// src/components/DropZone.jsx
import React, { useRef } from 'react';
import { Upload } from 'lucide-react';

const DropZone = ({ handleFiles, dragActive, setDragActive }) => {
  const fileInputRef = useRef(null);

  // Handle drag events
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  // Handle drop event
  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
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

  // Handle click on dropzone
  const onButtonClick = () => {
    fileInputRef.current.click();
  };

  return (
    <div 
      className={`drop-zone ${dragActive ? 'drop-zone-active' : ''}`}
      onDragEnter={handleDrag}
      onDragLeave={handleDrag}
      onDragOver={handleDrag}
      onDrop={handleDrop}
      onClick={onButtonClick}
    >
      <input
        ref={fileInputRef}
        className="file-input"
        type="file"
        onChange={handleChange}
      />
      <Upload size={48} className="upload-icon" />
      <p className="upload-text">Drag & drop your file here</p>
      <p className="upload-subtext">or click to browse</p>
      <button className="browse-button">Select File</button>
    </div>
  );
};

export default DropZone;