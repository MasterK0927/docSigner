/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */
// @ts-nocheck
import React, { useState, useRef, useEffect } from 'react';
import { pdfjs, Document, Page } from 'react-pdf';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';

pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  './pdfjs-dist-worker.js',
  import.meta.url,
).toString();

const ws = new WebSocket('ws://localhost:5000');

interface Props {
  onEnable?: () => void;
}

export function PdfRenderer(props: Props) {
  const [pdfFile, setPdfFile] = useState(null);
  const [numPages, setNumPages] = useState(null);
  const [pageNumber, setPageNumber] = useState(1);
  const [isSelecting, setIsSelecting] = useState(false);
  const [isSelectionEnabled, setIsSelectionEnabled] = useState(false);
  const [isSigned, setIsSigned] = useState(false);
  const [selectionCoords, setSelectionCoords] = useState({
    startX: 0,
    startY: 0,
    endX: 0,
    endY: 0,
  });
  const [pdfBuff, setPdfBuff] = useState(null);
  const overlayCanvasRefs = useRef([]);
  const pdfCanvasRefs = useRef([]);
  const pdfContainerRef = useRef(null);
  const pageRefs = useRef([]);

  useEffect(() => {
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.action === 'signed') {
        const signedPdfBuffer = new Uint8Array(
          Buffer.from(data.data, 'base64'),
        );
        setPdfFile(new Blob([signedPdfBuffer], { type: 'application/pdf' }));
        setIsSigned(true);
        setIsSelectionEnabled(false);
        showToast('Document signed successfully!', 'success');
      } else if (data.action === 'verified') {
        if (data.verified) {
          showToast('Document verification successful!', 'success');
        } else {
          showToast('Document verification failed.', 'error');
        }
      }
    };
  }, [pdfFile]);

  const handleFileInput = async (event) => {
    const file = event.target.files[0];
    if (file) {
      const arrayBuffer = await file.arrayBuffer();
      setPdfBuff(arrayBuffer);
      setPdfFile(new Blob([arrayBuffer], { type: 'application/pdf' }));
    }
  };

  const handleMouseDown = (event, pageIndex) => {
    if (!isSelectionEnabled) return;
    setIsSelecting(true);
    const pos = getMousePos(overlayCanvasRefs.current[pageIndex], event);
    setSelectionCoords({
      startX: pos.x,
      startY: pos.y,
      endX: pos.x,
      endY: pos.y,
    });
  };

  const handleMouseMove = (event, pageIndex) => {
    if (!isSelecting || !isSelectionEnabled) return;
    const pos = getMousePos(overlayCanvasRefs.current[pageIndex], event);
    setSelectionCoords((coords) => ({ ...coords, endX: pos.x, endY: pos.y }));
    drawSelection(pos.x, pos.y, pageIndex);
  };

  const handleMouseUp = (pageIndex) => {
    if (!isSelectionEnabled) return;
    setIsSelecting(false);
    embedSignature(pageIndex);
  };

  const embedSignature = (pageIndex) => {
    const { startX, startY, endX, endY } = selectionCoords;
    if (!pdfBuff) {
      console.error('PDF buffer is empty');
      return;
    }
    ws.send(
      JSON.stringify({
        action: 'sign',
        data: {
          pdfBuffer: Array.from(new Uint8Array(pdfBuff)),
          pageIndex,
          selectionCoords: { startX, startY, endX, endY },
        },
      }),
    );
  };

  const verifyDocument = () => {
    if (!pdfBuff) {
      console.error('PDF buffer is empty');
      return;
    }
    ws.send(
      JSON.stringify({
        action: 'verify',
        data: {
          Buff: Array.from(new Uint8Array(pdfBuff)),
        },
      }),
    );
  };

  const handleVerifyButtonClick = () => {
    if (pdfBuff) {
      verifyDocument();
    } else {
      showToast('Please upload a PDF first', 'error');
    }
  };

  const clearSelection = (pageIndex) => {
    setSelectionCoords({ startX: 0, startY: 0, endX: 0, endY: 0 });
    clearOverlay(pageIndex);
  };

  const handleSignButtonClick = () => {
    if (!pdfBuff) {
      showToast('Please upload a PDF first', 'error');
      return;
    }
    if (!isSigned) {
      setIsSelectionEnabled(true);
      console.log(
        'Selection tool enabled. Click and drag on the PDF to select an area.',
      );
    }
  };

  const handlePreviousPage = () => {
    if (pageNumber > 1) {
      setPageNumber(pageNumber - 1);
      scrollToPage(pageNumber - 1);
    }
  };

  const handleNextPage = () => {
    if (pageNumber < numPages) {
      setPageNumber(pageNumber + 1);
      scrollToPage(pageNumber + 1);
    }
  };

  const handlePageInputChange = (event) => {
    const newPageNumber = parseInt(event.target.value, 10);
    if (newPageNumber >= 1 && newPageNumber <= numPages) {
      setPageNumber(newPageNumber);
      scrollToPage(newPageNumber);
    }
  };

  const scrollToPage = (pageNum) => {
    const pageElement = pageRefs.current[pageNum - 1];
    if (pageElement) {
      pageElement.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const getMousePos = (canvas, evt) => {
    const rect = canvas.getBoundingClientRect();
    return {
      x: evt.clientX - rect.left,
      y: evt.clientY - rect.top,
    };
  };

  const drawSelection = (x, y, pageIndex) => {
    const canvas = overlayCanvasRefs.current[pageIndex];
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const { startX, startY } = selectionCoords;
    ctx.strokeStyle = 'red';
    ctx.lineWidth = 2;
    ctx.strokeRect(startX, startY, x - startX, y - startY);
  };

  const clearOverlay = (pageIndex) => {
    const canvas = overlayCanvasRefs.current[pageIndex];
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  };

  const onDocumentLoadSuccess = ({ numPages }) => {
    setNumPages(numPages);
  };

  const onPageLoadSuccess = (pageIndex) => {
    const canvas = pdfCanvasRefs.current[pageIndex];
    const overlayCanvas = overlayCanvasRefs.current[pageIndex];
    overlayCanvas.width = canvas.width;
    overlayCanvas.height = canvas.height;
  };

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const pageIndex = pageRefs.current.indexOf(entry.target) + 1;
            setPageNumber(pageIndex);
          }
        });
      },
      { root: pdfContainerRef.current, rootMargin: '0px', threshold: 0.7 },
    );

    pageRefs.current.forEach((page) => {
      if (page) observer.observe(page);
    });

    return () => {
      pageRefs.current.forEach((page) => {
        if (page) observer.unobserve(page);
      });
    };
  }, [numPages]);

  const showToast = (message, type) => {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerText = message;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('fade-out');
      toast.addEventListener('transitionend', () => toast.remove());
    }, 3000);
  };

  return (
    <>
      <div className="App" style={{ padding: '20px' }}>
        <div
          id="controls"
          style={{
            display: 'flex',
            justifyContent: 'center',
            marginBottom: '20px',
          }}
        >
          <input
            type="file"
            id="pdfInput"
            accept="application/pdf"
            onChange={handleFileInput}
            style={{ padding: '10px', marginRight: '10px' }}
          />
          <button
            id="signButton"
            onClick={handleSignButtonClick}
            style={{ padding: '10px', marginRight: '10px' }}
          >
            Sign
          </button>
          <button
            id="verifyButton"
            onClick={handleVerifyButtonClick}
            style={{ padding: '10px' }}
          >
            Verify
          </button>
        </div>
        <div
          id="pdfContainer"
          ref={pdfContainerRef}
          style={{ maxHeight: '80vh', overflowY: 'auto' }}
        >
          <Document file={pdfFile} onLoadSuccess={onDocumentLoadSuccess}>
            {Array.from(new Array(numPages), (el, index) => (
              <div key={index} ref={(el) => (pageRefs.current[index] = el)}>
                <Page
                  pageNumber={index + 1}
                  width={600}
                  onRenderSuccess={() => onPageLoadSuccess(index)}
                >
                  <canvas
                    ref={(el) => (pdfCanvasRefs.current[index] = el)}
                    style={{ display: 'none' }}
                  />
                  <canvas
                    ref={(el) => (overlayCanvasRefs.current[index] = el)}
                    style={{ position: 'absolute', top: 0, left: 0 }}
                    onMouseDown={(event) => handleMouseDown(event, index)}
                    onMouseMove={(event) => handleMouseMove(event, index)}
                    onMouseUp={() => handleMouseUp(index)}
                  />
                </Page>
              </div>
            ))}
          </Document>
          <div
            style={{
              display: 'flex',
              justifyContent: 'center',
              marginTop: '20px',
            }}
          >
            <button onClick={handlePreviousPage} disabled={pageNumber <= 1}>
              Previous
            </button>
            <input
              type="number"
              value={pageNumber}
              onChange={handlePageInputChange}
              min="1"
              max={numPages}
              style={{ margin: '0 10px' }}
            />
            <button onClick={handleNextPage} disabled={pageNumber >= numPages}>
              Next
            </button>
          </div>
        </div>
      </div>
      <style jsx>{`
        .toast {
          position: fixed;
          top: 20px;
          right: 20px;
          background-color: white;
          padding: 20px 40px;
          border-radius: 5px;
          box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.1);
          z-index: 1001;
          transition: opacity 0.3s ease;
          font-size: 16px;
        }
        .toast.success {
          background-color: green;
          color: white;
        }
        .toast.error {
          background-color: red;
          color: white;
        }
        .toast.fade-out {
          opacity: 0;
        }
      `}</style>
    </>
  );
}
