import crypto from "crypto";

/**
 * @event        Sender End
 * @description  Encrypt file using AES-256 and concat encrypted checksum
 */
const encryptFile = (
  fileBuffer: Buffer,
  encryptedChecksum: Buffer,
  key: crypto.CipherKey
) => {
  const iv = encryptedChecksum;

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([iv, cipher.update(fileBuffer)]);

  return encryptedBuffer;
};

export default encryptFile;
