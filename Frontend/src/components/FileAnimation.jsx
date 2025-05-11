// src/components/FileAnimation.jsx
import React from "react";

const FileAnimation = ({ x, y, onAnimationEnd }) => {
  return (
    <div
      className="file-animation"
      style={{ left: `${x}px`, top: `${y}px` }}
      onAnimationEnd={onAnimationEnd}
    />
  );
};

export default FileAnimation;
