import generateChecksum from "./generateChecksum";

const verifyChecksumAndFile = (
  receivedFile: Buffer,
  decryptedChecksum: string
) => {
  const checksum = generateChecksum(receivedFile);
  if (checksum != decryptedChecksum) {
    return false;
  }
  return true;
};

export default verifyChecksumAndFile;
