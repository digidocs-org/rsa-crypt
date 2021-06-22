import crypto from "crypto";

/**
 * @event        Sender End
 * @description  Encrypt checksum using private key
 */
const encryptFile = (
  checksum: Buffer,
  privateKey: crypto.RsaPrivateKey | crypto.KeyLike
) => {
  const encryptedChecksum = crypto.privateEncrypt(
    privateKey,
    Buffer.from(checksum)
  );
  return encryptedChecksum;
};

export default encryptFile;
