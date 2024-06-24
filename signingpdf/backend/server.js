const express = require('express');
const multer = require('multer');
const fs = require('fs');
const forge = require('node-forge');
const {
  plainAddPlaceholder,
  removeTrailingNewLine,
} = require('node-signpdf/dist/helpers/index');
const cors = require('cors');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const path = require('path');

const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';
const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(cors());
app.use(express.static('public'));

const addPlaceholder = async (pdfPath, signerName) => {
  try {
    const existingPdfBytes = await fs.promises.readFile(pdfPath);
    const pdfDoc = await PDFDocument.load(existingPdfBytes);
    const pages = pdfDoc.getPages();
    const firstPage = pages[0];

    // Adjust these values based on your PDF dimensions and desired positioning
    const boxLeft = 20;
    const boxBottom = 20;
    const boxWidth = 200;
    const boxHeight = 50;

    // Draw the rectangle
    firstPage.drawRectangle({
      x: boxLeft,
      y: firstPage.getHeight() - boxBottom - boxHeight,
      width: boxWidth,
      height: boxHeight,
      borderColor: rgb(0, 0, 0),
      borderWidth: 1,
    });

    // Add text inside the rectangle
    const now = new Date();
    const timestamp = `${now.toLocaleDateString()} ${now.toLocaleTimeString()}`;
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

    firstPage.drawText(`Signed by ${signerName} using Ping\n${timestamp}`, {
      x: boxLeft + 10,
      y: firstPage.getHeight() - boxBottom - boxHeight + 20,
      size: 12,
      font: font,
      color: rgb(0, 0, 0),
    });

    const modifiedPdfBytes = await pdfDoc.save({
      addDefaultPage: false,
      useObjectStreams: false,
    });
    await fs.promises.writeFile('modified.pdf', modifiedPdfBytes);

    return 'modified.pdf';
  } catch (error) {
    console.error('Error adding placeholder:', error);
    throw error;
  }
};

const signpdf = (pdfBuffer, certificate, signatureHash) => {
  // Extract signer's name from the certificate
  const signerName = certificate.subject.getField('CN').value;

  // Adding placeholder
  pdfBuffer = plainAddPlaceholder({
    pdfBuffer,
    reason: `Signed by ${signerName} using Ping`,
  });
  console.log('Added placeholder:', pdfBuffer.toString('utf8', 0, 200)); // Log first 200 bytes

  let pdf = removeTrailingNewLine(pdfBuffer);
  console.log(
    'PDF after removing trailing new lines:',
    pdf.toString('utf8', 0, 200),
  ); // Log first 200 bytes

  const byteRangePlaceholder = [
    0,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
  ];
  const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
  const byteRangePos = pdf.indexOf(byteRangeString);
  if (byteRangePos === -1) {
    console.error(`Could not find ByteRange placeholder: ${byteRangeString}`);
    throw new Error(`Could not find ByteRange placeholder: ${byteRangeString}`);
  }
  console.log(`ByteRange found at position: ${byteRangePos}`);

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
  console.log(
    'PDF with updated ByteRange:',
    pdf.toString('utf8', byteRangePos, byteRangePos + 200),
  ); // Log 200 bytes around the ByteRange

  pdf = Buffer.concat([
    pdf.slice(0, byteRange[1]),
    pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
  ]);
  console.log(
    'PDF with removed placeholder content:',
    pdf.toString('utf8', 0, 200),
  ); // Log first 200 bytes

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
    console.error(
      `Signature exceeds placeholder length: ${
        raw.length * 2
      } > ${placeholderLength}`,
    );
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

app.post(
  '/sign-pdf',
  upload.fields([{ name: 'pdf' }, { name: 'cert' }]),
  async (req, res) => {
    try {
      const pdfPath = req.files.pdf[0].path;
      const certPath = req.files.cert[0].path;
      console.log(`Received PDF: ${pdfPath}, Certificate: ${certPath}`);

      // Extract signer's name from the certificate
      const certPem = fs.readFileSync(certPath, 'utf8');
      console.log('certPem: ', certPem);
      const certc = new Uint8Array(certPath);
      console.log('certc: ', certc);
      const cert = forge.pki.certificateFromPem(certPem);
      const signerName = cert.subject.getField('CN').value;

      // Add visible placeholder to PDF
      const modifiedPdfPath = await addPlaceholder(pdfPath, signerName);
      const pdfBuffer = fs.readFileSync(modifiedPdfPath);

      console.log('PDF buffer length:', pdfBuffer.length);
      console.log('First 100 bytes of PDF:', pdfBuffer.toString('hex', 0, 100));

      const sigHash =
        '6129f7c2d451c87d0693deb397d2d06a714ba954bcc866e69d642779b4b0a06e0744c36d67b71c861c8d8255590dad87db5ac0d7fa983164374f57bb758f823249264acd9f9b044df7d8ab8a08e1b6cf0a868fea3a021b9ba899a720402a9beeab377a3d2a9e98a26ee4666fbde0fbe91678fae2b63add600dbeb94af126a494b5d26722409c46f18d64d7d68db027d88637d1cfd986341d2e0dd2844265b9e1754506c299d610946d2156395d2d673bdebbc778fde4457f3d133bcd7e03e057f23808523e6c144ccd649d1ce9da1c647145a9517753e2a4fea1909b6544c398485a099f08c8c0828ea31afc0c2be3e55f920a9ff5bbdec4596ae300e2622255';

      const signedPdf = signpdf(pdfBuffer, cert, sigHash);
      const signedPdfPath = `signed-${req.files.pdf[0].originalname}`;
      fs.writeFileSync(signedPdfPath, signedPdf);

      res.download(signedPdfPath, (err) => {
        if (err) console.error(err);
        fs.unlinkSync(pdfPath);
        fs.unlinkSync(signedPdfPath);
      });
    } catch (error) {
      console.error('Error signing PDF:', error);
      if (error.stack) {
        console.error('Error stack:', error.stack);
      }
      res.status(500).send('An error occurred while signing the PDF.');
    }
  },
);

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
