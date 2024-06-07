const { getDocument } = require('pdfjs');

async function verifyPDFSignatures(pdfURL) {
    const pdf = await getDocument(pdfURL).promise;

    const numPages = pdf.numPages;

    // Looping through each page to check for signatures
    for (let pageNum = 1; pageNum <= numPages; pageNum++) {
        const page = await pdf.getPage(pageNum);
        const annotations = await page.getAnnotations();

        // each annotation is checked for a signature
        for (let i = 0; i < annotations.length; i++) {
            const annotation = annotations[i];

            // if the annotation is a signature
            if (annotation.subtype === 'Widget' && annotation.fieldType === 'Sig') {
                // Extract the signature data
                const signatureData = annotation.signatureInfo;

                // Verify the signature
                const isValid = await verifySignature(signatureData);
                console.log(`Signature on page ${pageNum} is ${isValid ? 'valid' : 'invalid'}`);
            }
        }
    }
}

// verify the validity of a signature
async function verifySignature(signatureData) {
    //certificate
    const certificate = await getCertificate(signatureData.certificate);

    //Web Cryptography API for verifying the signature
    const publicKey = await crypto.subtle.importKey(
        'spki',
        certificate,
        { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
        false,
        ['verify']
    );

    // Verifying the signature
    const isValid = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
        publicKey,
        signatureData.signatureAlgorithm.parameters,
        signatureData.signatureValue
    );

    return isValid;
}

async function getCertificate(certificateURL) {
    const response = await fetch(certificateURL);
    const certificateData = await response.arrayBuffer();
    return certificateData;
}
const pdfURL = 'signed.pdf';
verifyPDFSignatures(pdfURL);
