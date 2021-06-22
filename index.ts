//https://obj.digidocs.one/06dbacf3-c79e-46de-9950-6507ba4e8092.pdf
const crypto = require("crypto");

const fetchFile = (
  url = "https://obj.digidocs.one/06dbacf3-c79e-46de-9950-6507ba4e8092.pdf"
) => fetch(url).then((res) => res.buffer());


let key = crypto.randomBytes(32);

// const signFile = (privateKey, file) => {
//   const signature = crypto.sign("sha256", Buffer.from(file), privateKey);
//   return signature.length;
// };

// const verifySign = async (signature, publicKey, file) => {
//   const isVerified = crypto.verify(
//     "sha256",
//     Buffer.from(file),
//     {
//       key: publicKey,
//       // padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
//     },
//     signature
//   );
//   return isVerified;
// };










const main = async () => {
  const fileBuffer = await fetchFile();
  const { publicKey, privateKey } = generateRSAkeys();

  //Sender's End
  const encryptedChecksum = generateAndEncryptChecksum(fileBuffer, privateKey);
  const encryptedFile = encryptFile(fileBuffer, encryptedChecksum);

  //Receiver's End
  const { decryptedChecksum, decryptedBuffer } = decryptFileAndChecksum(
    encryptedFile,
    publicKey
  );
  const isValidDocument = verifyChecksumAndFile(
    decryptedBuffer,
    decryptedChecksum
  );
  console.log(isValidDocument);
  // const signature = signFile(privateKey, fileBuffer);
  // console.log(verifySign(signature, publicKey, fileBuffer));
  // const encryptedData = console.log(encryptFile(fileBuffer, signature));
  // const isVerified = await verifySign(signature, publicKey, fileBuffer);
  // console.log(isVerified);
};

main();
