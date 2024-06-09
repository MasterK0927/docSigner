const forge = require('node-forge'); // Library for cryptographic operations
const crypto = require('crypto'); // Node.js crypto module for cryptographic operations
const fs = require('fs');
const path = require('path');

class PdfSignatureVerifier {
  // Extracts the signature and the signed data from the PDF content
  extractSignature(pdfContentBuffer) {
    try {
      // Find the position of ByteRange in the PDF
      let byteRangeStartPosition = pdfContentBuffer.lastIndexOf("/ByteRange[");
      if (byteRangeStartPosition === -1) {
        byteRangeStartPosition = pdfContentBuffer.lastIndexOf("/ByteRange [");
      }
      if (byteRangeStartPosition === -1) {
        throw new Error('ByteRange not found in the PDF');
      }

      // Determine the end of ByteRange
      const byteRangeEndPosition = pdfContentBuffer.indexOf("]", byteRangeStartPosition);
      const byteRangeString = pdfContentBuffer.slice(byteRangeStartPosition, byteRangeEndPosition + 1).toString();

      // Extract individual byte range values
      const byteRangeMatches = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(byteRangeString);
      if (!byteRangeMatches) {
        throw new Error('Invalid ByteRange format in the PDF');
      }

      const byteRangeValues = byteRangeMatches[0].split(" ");

      // Concatenate the parts of the signed data based on ByteRange
      const signedDataBuffer = Buffer.concat([
        pdfContentBuffer.slice(parseInt(byteRangeValues[0]), parseInt(byteRangeValues[1])),
        pdfContentBuffer.slice(parseInt(byteRangeValues[2]), parseInt(byteRangeValues[2]) + parseInt(byteRangeValues[3])),
      ]);

      // Extract the signature as a binary string
      let signatureHexString = pdfContentBuffer
       .slice(parseInt(byteRangeValues[0]) + (parseInt(byteRangeValues[1]) + 1), parseInt(byteRangeValues[2]) - 1)
       .toString('binary');

      // Remove trailing null bytes from the signature
      signatureHexString = signatureHexString.replace(/(?:00)*$/, '');
      const signatureBinaryBuffer = Buffer.from(signatureHexString, 'hex');

      return { signatureBinaryBuffer, signedDataBuffer };
    } catch (error) {
      console.error(`Error extracting signature: ${error.message}`);
      throw error;
    }
  }

  // Verifies the PDF signature
  verifySignature(pdfContentBuffer) {
    try {
      // Extract the signature and signed data from the PDF content
      const { signatureBinaryBuffer, signedDataBuffer } = this.extractSignature(pdfContentBuffer);

      // Parse the signature's ASN.1 structure
      const p7Asn1 = forge.asn1.fromDer(signatureBinaryBuffer);
      const pkcs7Message = forge.pkcs7.messageFromAsn1(p7Asn1);
      const { signature: signatureValue, digestAlgorithm, authenticatedAttributes } = pkcs7Message.rawCapture;

      // Create ASN.1 SET structure for the authenticated attributes
      const attributeSet = forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.SET,
        true,
        authenticatedAttributes
      );

      // Determine the hash algorithm used for signing
      const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
      const hashAlgorithmName = forge.pki.oids[hashAlgorithmOid].toUpperCase();

      // Create a buffer for the authenticated attributes
      const attributeBuffer = Buffer.from(forge.asn1.toDer(attributeSet).data, 'binary');
      const verifier = crypto.createVerify(`RSA-${hashAlgorithmName}`);
      verifier.update(attributeBuffer);

      // Extract the certificate for verification
      const certificatePem = forge.pki.certificateToPem(pkcs7Message.certificates[0]);
      const validAttributes = verifier.verify(certificatePem, signatureValue, 'binary');
      if (!validAttributes) {
        throw new Error('Invalid authenticated attributes');
      }

      // Hash the signed data for comparison
      const pdfHash = crypto.createHash(hashAlgorithmName);
      pdfHash.update(signedDataBuffer);

      // Extract the message digest from the authenticated attributes
      const messageDigestOid = forge.pki.oids.messageDigest;
      const messageDigestAttribute = authenticatedAttributes.find(
        (attr) => forge.asn1.derToOid(attr.value[0].value) === messageDigestOid
      );
      if (!messageDigestAttribute) {
        throw new Error('Message digest attribute not found');
      }
      const messageDigestValue = messageDigestAttribute.value[1].value[0].value;

      // Compare the computed hash of the signed data with the extracted message digest
      const computedHash = pdfHash.digest();
      const validDigest = computedHash.toString('binary') === messageDigestValue;

      if (validDigest) {
        console.log("Signature is valid!!!");
      } else {
        throw new Error("Invalid content digest");
      }
    } catch (error) {
      console.error(`Verification failed: ${error.message}`);
      throw error;
    }
  }
}

// Main function to verify the PDF signature
function main(pdfFilePath) {
  try {
    if (!fs.existsSync(pdfFilePath)) {
      throw new Error(`File not found: ${pdfFilePath}`);
    }

    const pdfContentBuffer = fs.readFileSync(pdfFilePath);
    const verifier = new PdfSignatureVerifier();
    verifier.verifySignature(pdfContentBuffer);
  } catch (error) {
    console.error(`Error in main: ${error.message}`);
  }
}

// Run the main function with the provided PDF file path
const pdfFilePath = path.resolve(__dirname, 'Schedule.pdf');
main(pdfFilePath);