import React, { useState } from 'react';

function App() {
  const [pdfFile, setPdfFile] = useState(null);
  const [certFile, setCertFile] = useState(null);

  const handlePdfChange = (e) => setPdfFile(e.target.files[0]);
  const handleCertChange = (e) => setCertFile(e.target.files[0]);

  const handleSignPdf = async () => {
    if (!pdfFile || !certFile) {
      alert('Please upload both PDF and certificate files.');
      return;
    }

    const formData = new FormData();
    formData.append('pdf', pdfFile);
    formData.append('cert', certFile);

    try {
      const response = await fetch('http://localhost:5000/sign-pdf', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `signed-${pdfFile.name}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (error) {
      console.error('Error signing PDF:', error);
    }
  };

  return (
    <div>
      <h1>Sign PDF</h1>
      <input type="file" onChange={handlePdfChange} accept="application/pdf" />
      <input type="file" onChange={handleCertChange} accept=".pem" />
      <button onClick={handleSignPdf}>Sign PDF</button>
    </div>
  );
}

export default App;
