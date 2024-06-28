import express from 'express';
import multer from 'multer';
import { promises as fsPromises } from 'fs';
import forge from 'node-forge';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { VerifyPdf } from './verifier/verify.js';

const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(express.json());

const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';

const addPlaceholder = async (
  pdfPath,
  signerName,
  pageIndex,
  selectionCoords,
) => {
  try {
    const existingPdfBytes = await fsPromises.readFile(pdfPath);
    const pdfDoc = await PDFDocument.load(existingPdfBytes);
    const page = pdfDoc.getPage(pageIndex);

    const { startX, startY, endX, endY } = selectionCoords;

    // Draw the rectangle
    page.drawRectangle({
      x: startX,
      y: page.getHeight() - endY,
      width: endX - startX,
      height: endY - startY,
      borderColor: rgb(0, 0, 0),
      borderWidth: 1,
    });

    // Add text inside the rectangle
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
    await fsPromises.writeFile('modified.pdf', modifiedPdfBytes);

    return 'modified.pdf';
  } catch (error) {
    console.error('Error adding placeholder:', error);
    throw error;
  }
};

const signpdf = async (pdfBuffer, certificate, signatureHash) => {
  try {
    const signerName = certificate.subject.getField('CN').value;

    // Adding placeholder
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
      throw new Error(
        `Could not find ByteRange placeholder: ${byteRangeString}`,
      );
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
  } catch (error) {
    console.error('Error signing PDF:', error);
    throw error;
  }
};

app.post('/v1/api/sign', upload.single('pdf'), async (req, res) => {
  try {
    const pdfPath = req.file.path;
    const { pageIndex, selectionCoords } = req.body;
    const { startX, startY, endX, endY } = JSON.parse(selectionCoords);

    console.log(`Received PDF: ${pdfPath}`);
    console.log(
      `Page index: ${pageIndex}, Selection coordinates: Start(${startX}, ${startY}) - End(${endX}, ${endY})`,
    );

    const certPem = await fsPromises.readFile(
      '/home/keshav/Desktop/certificate/certificate.pem',
      'utf8',
    );
    const cert = forge.pki.certificateFromPem(certPem);
    const signerName = cert.subject.getField('CN').value;

    const modifiedPdfPath = await addPlaceholder(
      pdfPath,
      signerName,
      pageIndex,
      { startX, startY, endX, endY },
    );
    const pdfBuffer = await fsPromises.readFile(modifiedPdfPath);

    console.log('PDF buffer length:', pdfBuffer.length);
    console.log('First 100 bytes of PDF:', pdfBuffer.toString('hex', 0, 100));

    const sigHash = '...'; // Replace this with your signature hash

    const signedPdf = await signpdf(pdfBuffer, cert, sigHash);
    const signedPdfPath = `signed-${req.file.originalname}`;
    await fsPromises.writeFile(signedPdfPath, signedPdf);

    res.download(signedPdfPath, (err) => {
      if (err) console.error(err);
      fsPromises.unlink(pdfPath);
      fsPromises.unlink(signedPdfPath);
    });
  } catch (error) {
    console.error('Error signing PDF:', error);
    if (error.stack) {
      console.error('Error stack:', error.stack);
    }
    res.status(500).send('An error occurred while signing the PDF.');
  }
});

app.post('/v1/api/verify', upload.single('pdf'), async (req, res) => {
  try {
    const pdfBuffer = await fsPromises.readFile(req.file.path);
    const verifier = new VerifyPdf();
    const isVerified = verifier.verify(pdfBuffer);

    res.status(200).json({ verified: isVerified });
  } catch (error) {
    console.error('Error verifying PDF:', error);
    res
      .status(500)
      .json({ error: 'An error occurred while verifying the PDF.' });
  }
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
