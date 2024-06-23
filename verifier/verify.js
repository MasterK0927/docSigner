import forge from 'node-forge';
import crypto from 'crypto';
import fs from 'fs';

export class VerifyPdf {
  getSignature(pdf) {
    let byteRangePos = pdf.lastIndexOf('/ByteRange[');
    if (byteRangePos === -1) byteRangePos = pdf.lastIndexOf('/ByteRange [');

    const byteRangeEnd = pdf.indexOf(']', byteRangePos);
    const byteRange = pdf.slice(byteRangePos, byteRangeEnd + 1).toString();
    const byteRangeNumbers = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(byteRange);
    const byteRangeArr = byteRangeNumbers[0].split(' ');

    const signedData = Buffer.concat([
      pdf.slice(parseInt(byteRangeArr[0]), parseInt(byteRangeArr[1])),
      pdf.slice(
        parseInt(byteRangeArr[2]),
        parseInt(byteRangeArr[2]) + parseInt(byteRangeArr[3]),
      ),
    ]);

    let signatureHex = pdf
      .slice(
        parseInt(byteRangeArr[0]) + (parseInt(byteRangeArr[1]) + 1),
        parseInt(byteRangeArr[2]) - 1,
      )
      .toString('binary');
    signatureHex = signatureHex.replace(/(?:00)*$/, '');
    const signature = Buffer.from(signatureHex, 'hex').toString('binary');

    console.log('==== Extracted Signature Data ====');
    console.log('Byte Range:', byteRange);
    console.log('Byte Range Numbers:', byteRangeNumbers);
    console.log('Byte Range Array:', byteRangeArr);
    console.log('Signed Data:', signedData);
    console.log('Signature Hex:', signatureHex);
    console.log('Signature:', signature);
    console.log('==================================');

    return { signature, signedData };
  }

  verify(pdf) {
    const extractedData = this.getSignature(pdf);

    console.log('==== Extracted Data ====');
    console.log('Extracted Signature:', extractedData.signature);
    console.log('Extracted Signed Data:', extractedData.signedData);
    console.log('========================');

    const p7Asn1 = forge.asn1.fromDer(extractedData.signature);

    console.log('==== PKCS#7 ASN.1 Structure ====');
    console.log(p7Asn1);
    console.log('================================');

    const message = forge.pkcs7.messageFromAsn1(p7Asn1);

    console.log('==== PKCS#7 Message ====');
    console.log(message);
    console.log('========================');

    const {
      signature: sig,
      digestAlgorithm,
      authenticatedAttributes: attrs,
    } = message.rawCapture;

    console.log('==== Signature Components ====');
    console.log('Signature:', sig);
    console.log('Digest Algorithm:', digestAlgorithm);
    console.log('Authenticated Attributes:', attrs);
    console.log('==============================');

    const set = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      attrs,
    );

    console.log('==== SET of Authenticated Attributes ====');
    console.log(set);
    console.log('=========================================');

    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toUpperCase();

    console.log('==== Hash Algorithm ====');
    console.log('Hash Algorithm OID:', hashAlgorithmOid);
    console.log('Hash Algorithm:', hashAlgorithm);
    console.log('========================');

    const buf = Buffer.from(forge.asn1.toDer(set).data, 'binary');
    const verifier = crypto.createVerify(`RSA-${hashAlgorithm}`);
    verifier.update(buf);

    console.log('==== Verifier ====');
    console.log(verifier);
    console.log('==================');

    const cert = forge.pki.certificateToPem(message.certificates[0]);

    console.log('==== Certificate ====');
    console.log(cert);
    console.log('=====================');

    const validAuthenticatedAttributes = verifier.verify(cert, sig, 'binary');

    console.log(
      '==== Valid Authenticated Attributes ====',
      validAuthenticatedAttributes,
    );
    console.log('========================================');

    if (!validAuthenticatedAttributes)
      throw new Error('Wrong authenticated attributes');

    const pdfHash = crypto.createHash(hashAlgorithm);

    console.log('==== PDF Hash ====');
    console.log(pdfHash);
    console.log('==================');

    const data = extractedData.signedData;
    pdfHash.update(data);

    console.log('==== Updated PDF Hash ====');
    console.log(pdfHash);
    console.log('==========================');

    const oids = forge.pki.oids;
    const fullAttrDigest = attrs.find(
      (attr) => forge.asn1.derToOid(attr.value[0].value) === oids.messageDigest,
    );
    const attrDigest = fullAttrDigest.value[1].value[0].value;

    console.log('==== Attribute Digest ====');
    console.log(attrDigest);
    console.log('==========================');

    const dataDigest = pdfHash.digest();

    console.log('==== Data Digest ====');
    console.log(dataDigest);
    console.log('=====================');

    const validContentDigest = dataDigest.toString('binary') === attrDigest;

    console.log('==== Valid Content Digest ====', validContentDigest);
    console.log('==============================');

    if (validContentDigest) {
      const greenText = '\x1b[32m%s\x1b[0m';
      console.log(greenText, 'Signature is valid!!!');
    } else {
      throw new Error('Wrong content digest');
    }
  }
}

function main() {
  const sign = new VerifyPdf();
  sign.verify(fs.readFileSync('/home/keshav/Desktop/pdf/signed-Sample.pdf'));
}

main();
