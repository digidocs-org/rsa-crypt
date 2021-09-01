import crypto from 'crypto';
import pem from 'pem'
import { promisify } from 'util'

interface ISignedParam {
    pfxFile: Buffer,
    fileBuffer: Buffer,
    password: string
}

const generateSign = (data: ISignedParam, callback: Function) => {
    const { pfxFile, password, fileBuffer } = data
    pem.readPkcs12(pfxFile, { p12Password: password }, (err, data) => {
        if (err) return callback(err, null)
        const privateKey = data.key
        const publicKey = data.cert

        const sign = crypto.sign("SHA256", fileBuffer, privateKey)
        const signature = sign.toString("base64")

        const xmlToSign = `<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>` +
            `<EsignResp errCode=\"NA\" errMsg=\"NA\" resCode=\"44B62B382E8345C2BE731ADBDDC5191B\" status=\"1\" ts=\"2021-08-01T00:30:01\" txn=\"asdfad89asfhe3\">` +
            `<UserX509Certificate>${publicKey}</UserX509Certificate>` +
            `<Signatures>` +
            `<DocSignature error="" id = "1" sigHashAlgorithm = "SHA256" >${signature}< /DocSignature>` +
            `</Signatures>`
        return callback(null, xmlToSign)
    })
}

export const generateXMLToSign = promisify(generateSign)