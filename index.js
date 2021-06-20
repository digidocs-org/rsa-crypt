//https://obj.digidocs.one/06dbacf3-c79e-46de-9950-6507ba4e8092.pdf
const crypto = require("crypto");
const fetch = require("node-fetch");

const fetchFile = (
  url = "https://obj.digidocs.one/06dbacf3-c79e-46de-9950-6507ba4e8092.pdf"
) => fetch(url).then((res) => res.buffer());

const generateRSAkeys = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
};

let key = crypto.randomBytes(32);

const signFile = (privateKey, file) => {
  const signature = crypto.sign("sha256", Buffer.from(file), privateKey);
  return signature.length;
};

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

const generateChecksum = (file) =>
  crypto.createHash("sha256").update(Buffer.from(file)).digest("base64");

/**
 * @event        Sender End
 * @description  Generate checksum and encrypt using private key
 */
const generateAndEncryptChecksum = (file, privateKey) => {
  const checksum = generateChecksum(file);

  const encryptedChecksum = crypto.privateEncrypt(
    privateKey,
    Buffer.from(checksum)
  );
  return encryptedChecksum;
};

/**
 * @event        Sender End
 * @description  Encrypt file using AES-256 and concat encrypted checksum
 */
const encryptFile = (fileBuffer, encryptedChecksum) => {
  const iv = encryptedChecksum;

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([iv, cipher.update(fileBuffer)]);

  //Store this buffer along with public key in AWS S3
  return encryptedBuffer;
};

/**
 * @event        Receiver End
 * @description  Decrypt file and checksum
 */
const decryptFileAndChecksum = (encryptedBuffer, publicKey) => {
  const iv = encryptedBuffer.slice(0, 256);
  encryptedBuffer = encryptedBuffer.slice(256);
  const decryptedChecksum = crypto.publicDecrypt(publicKey, iv).toString();

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  const decryptedBuffer = decipher.update(encryptedBuffer);

  return { decryptedChecksum, decryptedBuffer };
};

const verifyChecksumAndFile = (receivedFile, decryptedChecksum) => {
  const checksum = generateChecksum(receivedFile);
  if (checksum != decryptedChecksum) {
    return false;
  }
  return true;
};

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
