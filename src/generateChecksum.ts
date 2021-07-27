import crypto, { BinaryToTextEncoding } from "crypto";


/**
 * @info default type is base64
 */
const generateChecksum = (file: Buffer, type: BinaryToTextEncoding = "base64") =>
  crypto.createHash("sha256").update(Buffer.from(file)).digest(type);

export default generateChecksum;