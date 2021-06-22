import crypto from "crypto";

const generateRSAkeys = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
};

export default generateRSAkeys;
