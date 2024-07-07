import { promises as fsPromises } from 'fs';
import forge from 'node-forge';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import WebSocket, { WebSocketServer } from 'ws';
import { VerifyPdf } from './verifier/verify.js';
import {
  plainAddPlaceholder,
  removeTrailingNewLine,
} from 'node-signpdf/dist/helpers/index.js';

const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';

const addPlaceholder = async (
  pdfBuffer,
  signerName,
  pageIndex,
  selectionCoords,
) => {
  try {
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    const page = pdfDoc.getPage(pageIndex);

    const { startX, startY, endX, endY } = selectionCoords;

    page.drawRectangle({
      x: startX,
      y: page.getHeight() - endY,
      width: endX - startX,
      height: endY - startY,
      borderColor: rgb(0, 0, 0),
      borderWidth: 1,
    });

    const now = new Date();
    const timestamp = `${now.toLocaleDateString()} ${now.toLocaleTimeString()}`;
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

    page.drawText(`Signed by ${signerName} using Ping\n${timestamp}`, {
      x: startX + 10,
      y: page.getHeight() - endY + 20,
      size: 12,
      font: font,
      color: rgb(0, 0, 0),
    });

    const modifiedPdfBytes = await pdfDoc.save({
      addDefaultPage: false,
      useObjectStreams: false,
    });

    return Buffer.from(modifiedPdfBytes);
  } catch (error) {
    console.error('Error adding placeholder:', error);
    throw error;
  }
};

const signpdf = (pdfBuffer, certificate, signatureHash) => {
  const signerName = certificate.subject.getField('CN').value;

  pdfBuffer = plainAddPlaceholder({
    pdfBuffer,
    reason: `Signed by ${signerName} using Ping`,
  });

  let pdf = removeTrailingNewLine(pdfBuffer);

  const byteRangePlaceholder = [
    0,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
  ];
  const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
  const byteRangePos = pdf.indexOf(byteRangeString);

  if (byteRangePos === -1) {
    throw new Error(`Could not find ByteRange placeholder: ${byteRangeString}`);
  }

  const byteRangeEnd = byteRangePos + byteRangeString.length;
  const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
  const placeholderPos = pdf.indexOf('<', contentsTagPos);
  const placeholderEnd = pdf.indexOf('>', placeholderPos);
  const placeholderLengthWithBrackets = placeholderEnd + 1 - placeholderPos;
  const placeholderLength = placeholderLengthWithBrackets - 2;
  const byteRange = [0, 0, 0, 0];
  byteRange[1] = placeholderPos;
  byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
  byteRange[3] = pdf.length - byteRange[2];
  let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
  actualByteRange += ' '.repeat(
    byteRangeString.length - actualByteRange.length,
  );

  pdf = Buffer.concat([
    pdf.slice(0, byteRangePos),
    Buffer.from(actualByteRange),
    pdf.slice(byteRangeEnd),
  ]);

  pdf = Buffer.concat([
    pdf.slice(0, byteRange[1]),
    pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
  ]);

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(pdf.toString('binary'));
  p7.addCertificate(certificate);
  p7.addSigner({
    key: { sign: () => signatureHash },
    certificate,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });
  p7.sign({ detached: true });
  const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
  if (raw.length * 2 > placeholderLength) {
    throw new Error(
      `Signature exceeds placeholder length: ${
        raw.length * 2
      } > ${placeholderLength}`,
    );
  }
  let signature = Buffer.from(raw, 'binary').toString('hex');
  signature += Buffer.from(
    String.fromCharCode(0).repeat(placeholderLength / 2 - raw.length),
  ).toString('hex');

  pdf = Buffer.concat([
    pdf.slice(0, byteRange[1]),
    Buffer.from(`<${signature}>`),
    pdf.slice(byteRange[1]),
  ]);

  return pdf;
};

const server = new WebSocketServer({ port: 5000 });

server.on('connection', (ws) => {
  ws.on('message', async (message) => {
    let parsedMessage;
    try {
      parsedMessage = JSON.parse(message);
    } catch (error) {
      console.error('Error parsing message:', error);
      ws.send(
        JSON.stringify({ action: 'error', message: 'Invalid message format' }),
      );
      return;
    }

    const { action, data } = parsedMessage;

    switch (action) {
      case 'sign':
        try {
          const { pdfBuffer, pageIndex, selectionCoords } = data;
          if (!pdfBuffer || pageIndex === undefined || !selectionCoords) {
            throw new Error('Missing required data for signing');
          }

          // Connect to browser extension
          const extensionWs = new WebSocket('ws://localhost:extension-port');

          extensionWs.on('open', () => {
            // Request certificate and signature
            const md_hash = forge.md.sha256
              .create()
              .update(pdfBuffer)
              .digest()
              .toHex();
            extensionWs.send(
              JSON.stringify({ action: 'getCertAndSign', data: { md_hash } }),
            );
          });

          extensionWs.on('message', async (extMessage) => {
            const { cert, signedHash } = JSON.parse(extMessage);

            const certificate = forge.pki.certificateFromPem(cert);
            const signerName = certificate.subject.getField('CN').value;

            // Add placeholder
            const pdfWithPlaceholder = await addPlaceholder(
              Buffer.from(pdfBuffer),
              signerName,
              pageIndex,
              selectionCoords,
            );

            // Sign PDF
            const signedPdf = signpdf(
              pdfWithPlaceholder,
              certificate,
              signedHash,
            );

            // Send signed PDF back to original connection
            ws.send(
              JSON.stringify({
                action: 'signed',
                data: signedPdf.toString('base64'),
              }),
            );

            extensionWs.close();
          });

          extensionWs.on('error', (error) => {
            console.error('WebSocket error with extension:', error);
            ws.send(
              JSON.stringify({
                action: 'error',
                message: 'Error communicating with extension',
              }),
            );
          });
        } catch (error) {
          console.error('Error signing PDF:', error);
          ws.send(
            JSON.stringify({
              action: 'error',
              message: 'Error signing PDF: ' + error.message,
            }),
          );
        }
        break;

      case 'verify':
        try {
          const { Buff } = data;
          if (!Buff) {
            throw new Error('Missing PDF buffer for verification');
          }

          const pdfBuffer = Buffer.from(new Uint8Array(Buff));
          const verifier = new VerifyPdf();
          const isVerified = await verifier.verify(pdfBuffer);

          ws.send(JSON.stringify({ action: 'verified', verified: isVerified }));
        } catch (error) {
          console.error('Error verifying PDF:', error);
          ws.send(
            JSON.stringify({
              action: 'error',
              message: 'Error verifying PDF: ' + error.message,
            }),
          );
        }
        break;

      default:
        ws.send(JSON.stringify({ action: 'error', message: 'Unknown action' }));
        break;
    }
  });
});

console.log('WebSocket server is running on port 5000');
