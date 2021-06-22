import crypto from "crypto";
import decryptChecksum from "./decryptChecksum";

/**
 * @event        Receiver End
 * @description  Decrypt file and checksum
 */
const decryptFileAndChecksum = (
  encryptedBuffer: Buffer,
  publicKey: crypto.RsaPublicKey | crypto.KeyLike,
  key: crypto.CipherKey
) => {
  const iv = encryptedBuffer.slice(0, 256);
  encryptedBuffer = encryptedBuffer.slice(256);
  const decryptedChecksum = decryptChecksum(publicKey, iv);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  const decryptedBuffer = decipher.update(encryptedBuffer);

  return { decryptedChecksum, decryptedBuffer };
};

export default decryptFileAndChecksum;
