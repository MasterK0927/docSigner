import forge from 'node-forge'; // Importing node-forge for cryptographic operations
import crypto from 'crypto'; // Importing Node.js crypto module for cryptographic functions
import fs from 'fs'; // Importing Node.js fs module for file system operations

export class VerifyPdf {
  // Method to extract signature and signed data from the PDF
  getSignature(pdf) {
    let byteRangePos = pdf.lastIndexOf('/ByteRange['); // Find the position of "/ByteRange["
    if (byteRangePos === -1) byteRangePos = pdf.lastIndexOf('/ByteRange ['); // Also check for "/ByteRange ["

    const byteRangeEnd = pdf.indexOf(']', byteRangePos); // Find the end of the byte range
    const byteRange = pdf.slice(byteRangePos, byteRangeEnd + 1).toString(); // Extract the byte range string
    const byteRangeNumbers = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(byteRange); // Extract byte range numbers
    const byteRangeArr = byteRangeNumbers[0].split(' '); // Split byte range numbers

    // Extract the signed data based on byte offsets
    const signedData = Buffer.concat([
      pdf.slice(parseInt(byteRangeArr[0]), parseInt(byteRangeArr[1])),
      pdf.slice(
        parseInt(byteRangeArr[2]),
        parseInt(byteRangeArr[2]) + parseInt(byteRangeArr[3]),
      ),
    ]);

    // Extract the signature bytes
    let signatureHex = pdf
      .slice(
        parseInt(byteRangeArr[0]) + (parseInt(byteRangeArr[1]) + 1),
        parseInt(byteRangeArr[2]) - 1,
      )
      .toString('binary');
    signatureHex = signatureHex.replace(/(?:00)*$/, ''); // Remove trailing null bytes
    const signature = Buffer.from(signatureHex, 'hex').toString('binary'); // Convert signature to binary string
    return { signature, signedData }; // Return extracted signature and signed data
  }

  // Method to verify the PDF signature
  verify(pdf) {
    // Extracting the message from the signature
    const extractedData = this.getSignature(pdf); // Get signature and signed data from PDF
    const p7Asn1 = forge.asn1.fromDer(extractedData.signature); // Parse ASN.1 structure from DER-encoded signature
    const message = forge.pkcs7.messageFromAsn1(p7Asn1); // Parse PKCS#7 message from ASN.1 structure

    // Extract necessary components for verification
    const {
      signature: sig,
      digestAlgorithm,
      authenticatedAttributes: attrs, // Authenticated attributes
    } = message.rawCapture;

    // Create SET of authenticated attributes
    const set = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      attrs,
    );

    // Find hash algorithm OID
    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toUpperCase(); // Get hash algorithm

    // Create verifier using RSA and hash algorithm
    const buf = Buffer.from(forge.asn1.toDer(set).data, 'binary');
    const verifier = crypto.createVerify(`RSA-${hashAlgorithm}`);
    verifier.update(buf); // Update verifier with SET of authenticated attributes

    // Verify the signature against the certificate
    const cert = forge.pki.certificateToPem(message.certificates[0]); // Get PEM-formatted certificate
    const validAuthenticatedAttributes = verifier.verify(cert, sig, 'binary');
    if (!validAuthenticatedAttributes)
      throw new Error('Wrong authenticated attributes');

    // Calculate hash of the non-signature part of PDF
    const pdfHash = crypto.createHash(hashAlgorithm);
    const data = extractedData.signedData;
    pdfHash.update(data);

    // Extract message digest from authenticated attributes
    const oids = forge.pki.oids;
    const fullAttrDigest = attrs.find(
      (attr) => forge.asn1.derToOid(attr.value[0].value) === oids.messageDigest,
    );
    const attrDigest = fullAttrDigest.value[1].value[0].value;

    // Compare message digest to computed PDF hash
    const dataDigest = pdfHash.digest();
    const validContentDigest = dataDigest.toString('binary') === attrDigest;
    if (validContentDigest) {
      const greenText = '\x1b[32m%s\x1b[0m';
      console.log(greenText, 'Signature is valid!!!'); // Output if signature is valid
    } else {
      throw new Error('Wrong content digest'); // Throw error if content digest does not match
    }
  }
}

// Main function to run verification
function main() {
  const sign = new VerifyPdf();
  sign.verify(fs.readFileSync('signed.pdf')); // Read and verify the specified PDF
}

main(); // Execute main function
