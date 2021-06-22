import crypto from "crypto";

/**
 * @event        Sender End
 * @description  Encrypt file using AES-256 and concat encrypted checksum
 */
const encryptFile = (fileBuffer: Buffer, encryptedChecksum: Buffer) => {
  const iv = encryptedChecksum;

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([
    iv,
    cipher.update(fileBuffer),
    Buffer.from("naman singh"),
  ]);

  return encryptedBuffer;
};

export default encryptFile;
