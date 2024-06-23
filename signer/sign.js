const fs = require('fs');
const forge = require('node-forge');
const pki = forge.pki;
const HELPERS = require('node-signpdf/dist/helpers');
const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';

const signpdf = (pdfBuffer, certificate, signatureHash) => {
  pdfBuffer = HELPERS.plainAddPlaceholder({ pdfBuffer, reason: 'reason' });
  let pdf = HELPERS.removeTrailingNewLine(pdfBuffer);
  const byteRangePlaceholder = [
    0,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
    `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
  ];
  const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
  const byteRangePos = pdf.indexOf(byteRangeString);
  console.log(byteRangePos);
  if (byteRangePos === -1)
    throw new Error(`Could not find ByteRange placeholder: ${byteRangeString}`);
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

  let signer = {};
  signer.sign = (md, algo) => {
    // https://stackoverflow.com/a/47106124
    const prefix = Buffer.from([
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ]);
    let buf = Buffer.concat([Buffer.from(signatureHash, 'hex')]);
    return (
      '®{æNg\x06Ç±K¬îYY}ú½8G\x12\x8AÓFK µ\x94É\\\x91\tÒ\x838~\x87]\x8AúÁÎ\x90\x14Èw$ ÀG"\x03-ÇÑå`\x04,]~\x9A<-LÄ\bïyÚë6H\x1BT\x0FÑ\n' +
      '.O\x10Æ?X\x8At Ý>M\x97ípó3æl\x87p_ÄR¢þW®="\x96Z¼²¢µÁ\x15Bm\x99Î\biu)» ÓõëìZÈNR\x94cÙ\x80{z®LÉsöOa7oÝ1pÙ\x86(.Å\x07´Cì?®Ï÷\x10wT%ÞÒUªÑÑ5\x05ÉüþqÆ¦¯w\x1D\\\x12÷xéð9\x88\x9B®Iz{Á\x17=\x91\x7Ft²<\x8D\x8Fi&\fQâÁ|ÄâåÒ4În¡ö\x06\x97\x1E\x91ß\t\x13c¹rÙdH²µ¶ÒO\x82\x9E£\x02Ô\n' +
      'Ã©Ló­\x98,ÀË'
    );
    return buf.toString('binary');
  };

  p7.addSigner({
    // key: { sign: () => signatureHash },
    key: signer,
    certificate,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data,
      },
      {
        type: forge.pki.oids.messageDigest,
        // value will be auto-populated at signing time
      },
      {
        type: forge.pki.oids.signingTime,
        // value can also be auto-populated at signing time
        // We may also support passing this as an option to sign().
        // Would be useful to match the creation time of the document for example.
        value: new Date(),
      },
    ],
  });
  p7.sign({ detached: true });
  const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
  console.log(raw);
  if (raw.length * 2 > placeholderLength)
    throw new Error(
      `Signature exceeds placeholder length: ${
        raw.length * 2
      } > ${placeholderLength}`,
    );
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

const testSignPDF = (pdfFile, certFile, sigHash) => {
  const pdfBuffer = fs.readFileSync(pdfFile);
  const certPem = fs.readFileSync(certFile, 'utf8');
  const cert = forge.pki.certificateFromPem(certPem);
  const signedPdf = signpdf(pdfBuffer, cert, sigHash);
  fs.writeFileSync('signed-out.pdf', signedPdf);
  return signedPdf;
};

// Usage example
const pdfFile = 'Sample.pdf';
const certFile = 'uday-cert.pem';
const sigHash =
  '6129f7c2d451c87d0693deb397d2d06a714ba954bcc866e69d642779b4b0a06e0744c36d67b71c861c8d8255590dad87db5ac0d7fa983164374f57bb758f823249264acd9f9b044df7d8ab8a08e1b6cf0a868fea3a021b9ba899a720402a9beeab377a3d2a9e98a26ee4666fbde0fbe91678fae2b63add600dbeb94af126a494b5d26722409c46f18d64d7d68db027d88637d1cfd986341d2e0dd2844265b9e1754506c299d610946d2156395d2d673bdebbc778fde4457f3d133bcd7e03e057f23808523e6c144ccd649d1ce9da1c647145a9517753e2a4fea1909b6544c398485a099f08c8c0828ea31afc0c2be3e55f920a9ff5bbdec4596ae300e2622255';

const signedPdf = testSignPDF(pdfFile, certFile, sigHash);
