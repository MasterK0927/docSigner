const fs = require('fs');
const { PDFDocument, rgb, PDFName, PDFHexString, PDFDict, PDFArray } = require('pdf-lib');

async function signPdfWithSignedHash(pdfPath, outputPath, signedHash) {
  try {
    // Loading the PDF document into a byteArray
    const existingPdfBytes = fs.readFileSync(pdfPath);
    const pdfDoc = await PDFDocument.load(existingPdfBytes);

    // Adding a signature placeholder
    const pages = pdfDoc.getPages();
    const firstPage = pages[0];
    const { width, height } = firstPage.getSize();
    firstPage.drawText('Signature Placeholder', {
      x: 50,
      y: height - 50,
      size: 12,
      color: rgb(0, 0, 0),
    });

    // Converting the signed hash from base64 to a hex string
    const signedHashBuffer = Buffer.from(signedHash, 'base64');
    const signedHashHex = PDFHexString.of(signedHashBuffer.toString('hex'));

    // Creating a signature dictionary
    const sigDict = pdfDoc.context.obj({
      Type: 'Sig',
      Filter: 'Adobe.PPKLite',
      SubFilter: 'adbe.pkcs7.detached',
      ByteRange: PDFArray.withContext(pdfDoc.context).push(
        0,                       // Placeholder start
        0,                       // Placeholder length
        0,                       // Placeholder length
        signedHashBuffer.length  // Length of the signed hash
      ),
      Contents: signedHashHex,
      Reason: 'Document signed digitally',
      M: new Date().toISOString(),
    });

    // Creating a signature field and adding the signature dictionary to it
    const sigField = pdfDoc.context.obj({
      FT: PDFName.of('Sig'),
      T: PDFName.of('Signature1'),
      V: sigDict,
      Rect: [0, 0, 0, 0],
    });

    // Ensuring that the AcroForm exists, creating it if not
    let acroForm = pdfDoc.catalog.lookup(PDFName.of('AcroForm'));
    if (!acroForm) {
      acroForm = pdfDoc.context.obj({
        Fields: [],
      });
      pdfDoc.catalog.set(PDFName.of('AcroForm'), acroForm);
    }

    console.log(acroForm);

    // Adding the signature field to the AcroForm fields
    const acroFormFields = acroForm.lookup(PDFName.of('Fields'), PDFArray);
    acroFormFields.push(sigField);

    // Save the signed PDF
    const modifiedPdfBytes = await pdfDoc.save();
    fs.writeFileSync(outputPath, modifiedPdfBytes);
    console.log('PDF signed and saved successfully.');
  } catch (error) {
    console.error('Error signing PDF:', error);
  }
}

const pdfPath = 'Schedule.pdf';

const outputPath = 'signed-document.pdf';

//signed hash (base64-encoded) for poc
const demoSignedHash = 'ZmFrZVNpZ25lZEhhc2hGb3JQT0M='; // 'fakeSignedHashForPOC' in base64

signPdfWithSignedHash(pdfPath, outputPath, demoSignedHash);
