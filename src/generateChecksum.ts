import crypto from "crypto";

const generateChecksum = (file: Buffer) =>
  crypto.createHash("sha256").update(Buffer.from(file)).digest("base64");

export default generateChecksum;
