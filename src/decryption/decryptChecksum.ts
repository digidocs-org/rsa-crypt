import crypto from "crypto";

const decryptChecksum = (
  publicKey: crypto.RsaPublicKey | crypto.KeyLike,
  buffer: Buffer
) => crypto.publicDecrypt(publicKey, buffer).toString();

export default decryptChecksum;
