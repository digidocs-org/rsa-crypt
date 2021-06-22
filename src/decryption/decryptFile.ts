import crypto from "crypto";

/**
 * @event        Receiver End
 * @description  Decrypt file and checksum
 */
const decryptFileAndChecksum = (
  encryptedBuffer: Buffer,
  publicKey: crypto.RsaPublicKey | crypto.KeyLike
) => {
  const iv = encryptedBuffer.slice(0, 256);
  encryptedBuffer = encryptedBuffer.slice(256);
  const decryptedChecksum = crypto.publicDecrypt(publicKey, iv).toString();

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  const decryptedBuffer = decipher.update(encryptedBuffer);

  return { decryptedChecksum, decryptedBuffer };
};

export default decryptFileAndChecksum;
