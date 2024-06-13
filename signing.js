const fs = require('fs');
const { PDFDocument, rgb, PDFName, PDFHexString, PDFDict, PDFArray } = require('pdf-lib');
const forge = require('node-forge');

async function signAndVerifyPdf(pdfPath, outputPath, certificatePath, privateKeyPem) {
  try {
    // Load the certificate from file
    const certificatePem = fs.readFileSync(certificatePath, 'utf-8');
    const forgeCert = forge.pki.certificateFromPem(certificatePem);

    // Load the private key from file (or you can generate one for testing)
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

    // Load the PDF document
    const existingPdfBytes = fs.readFileSync(pdfPath);
    const pdfDoc = await PDFDocument.load(existingPdfBytes);

    // Create a placeholder for the signature
    const pages = pdfDoc.getPages();
    const firstPage = pages[0];
    const { width, height } = firstPage.getSize();
    firstPage.drawText('Signature Placeholder', {
      x: 50,
      y: height - 50,
      size: 12,
      color: rgb(0, 0, 0),
    });

    // Serialize the PDF document
    const pdfBytes = await pdfDoc.save({ useObjectStreams: false });

    // Create the ByteRange placeholder
    const byteRange = [0, 0, 0, 0];
    const byteRangePlaceholder = '/ByteRange [ ' + byteRange.join(' ') + ' ]';

    // Define the signature dictionary
    const signatureDict = {
      Type: 'Sig',
      Filter: 'Adobe.PPKLite',
      SubFilter: 'adbe.pkcs7.detached',
      ByteRange: byteRangePlaceholder,
      Contents: '',
      Reason: 'Document signed digitally',
      M: new Date().toISOString(),
      Cert: certificatePem
    };

    // Embed the signature dictionary into the PDF
    const sigDict = pdfDoc.context.obj(signatureDict);
    const sigField = pdfDoc.context.obj({
      FT: PDFName.of('Sig'),
      T: PDFName.of('Signature1'),
      V: sigDict,
      Rect: [0, 0, 0, 0],
    });

    // Ensure the AcroForm exists
    let acroForm = pdfDoc.catalog.lookup(PDFName.of('AcroForm'));
    if (!acroForm) {
      acroForm = pdfDoc.context.obj({
        Fields: [],
      });
      pdfDoc.catalog.set(PDFName.of('AcroForm'), acroForm);
    }

    // Add the signature field to the AcroForm fields
    const acroFormFields = acroForm.lookup(PDFName.of('Fields'), PDFArray);
    acroFormFields.push(sigField);

    // Save the PDF document with the placeholder
    const modifiedPdfBytes = await pdfDoc.save();

    // Sign the placeholder using the private key
    const signedBytes = signPdf(modifiedPdfBytes, privateKey, certificatePem);

    if (!signedBytes) {
      throw new Error('Failed to sign the document.');
    }

    // Save the final signed PDF
    fs.writeFileSync(outputPath, signedBytes);
    console.log('PDF signed and saved successfully.');

    // Verify the signed PDF
    const verified = await verifyPdfSignature(outputPath, certificatePem);
    if (verified) {
      console.log('Signature verified successfully.');
      return signedBytes;
    } else {
      console.error('Signature verification failed.');
      return null;
    }
  } catch (error) {
    console.error('Error signing or verifying PDF:', error);
  }
}

function signPdf(pdfBytes, privateKey, certificatePem) {
  try {
    // Hash the PDF content
    const hash = forge.md.sha256.create();
    hash.update(pdfBytes);
    const hashBuffer = Buffer.from(hash.digest().bytes(), 'binary');

    // Sign the hash with the private key
    const signature = privateKey.sign(hashBuffer, 'RSASSA-PKCS1-V1_5-SIGN');

    // Embed the signed hash into the PDF
    const signatureHex = Buffer.from(signature).toString('hex');
    const signatureBytes = Buffer.from(signatureHex, 'hex');

    // Update the ByteRange
    const byteRangePlaceholder = '/ByteRange [';
    const byteRangeStart = pdfBytes.indexOf(byteRangePlaceholder) + byteRangePlaceholder.length;
    const byteRangeEnd = byteRangeStart + 48;
    const byteRange = [0, byteRangeStart, byteRangeStart + signatureBytes.length, pdfBytes.length - (byteRangeStart + signatureBytes.length)];
    const byteRangeString = byteRange.join(' ');

    // Embed the signed hash
    const finalPdfBytes = Buffer.concat([
      Buffer.from(pdfBytes.slice(0, byteRangeStart)),
      Buffer.from(byteRangeString),
      Buffer.from(pdfBytes.slice(byteRangeEnd, byteRange[2])),
      signatureBytes,
      Buffer.from(pdfBytes.slice(byteRange[3]))
    ]);

    return finalPdfBytes;
  } catch (error) {
    console.error('Error during signing:', error);
    return null;
  }
}

async function verifyPdfSignature(pdfPath, certificatePem) {
  try {
    // Load the PDF document
    const existingPdfBytes = fs.readFileSync(pdfPath);
    const pdfDoc = await PDFDocument.load(existingPdfBytes);

    // Extract the AcroForm and signature field
    const acroForm = pdfDoc.catalog.lookup(PDFName.of('AcroForm'), PDFDict);
    const fields = acroForm.lookup(PDFName.of('Fields'), PDFArray);
    const sigField = fields.lookup(0, PDFDict);
    const sigDict = sigField.lookup(PDFName.of('V'), PDFDict);

    // Extract the signature contents
    const contentsHex = sigDict.lookup(PDFName.of('Contents')).decodeText();
    const contentsBuffer = Buffer.from(contentsHex, 'hex');
    const signature = contentsBuffer.toString('base64');

    // Verify the signature
    const forgeCert = forge.pki.certificateFromPem(certificatePem);
    const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(signature));
    const verified = p7.verify({
      detached: true,
      content: existingPdfBytes,
      certificates: [forgeCert],
    });

    return verified;
  } catch (error) {
    console.error('Error verifying PDF signature:', error);
    return false;
  }
}

// Paths to the PDF and output file
const pdfPath = 'Schedule.pdf';
const outputPath = 'signed-document.pdf';

// Path to the .cer certificate file
const certificatePath = 'uday-cert.cer';

// Path to the private key PEM file (for testing)
const privateKeyPem = 'path/to/your/private-key.pem';

// Sign and verify the PDF
signAndVerifyPdf(pdfPath, outputPath, certificatePath, privateKeyPem);
