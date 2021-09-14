import pem from "pem";
import util from 'util'
import { SignedXml } from 'xml-crypto'

interface ISignedParam {
    pfxFile: Buffer
    password: string
    xml: string
}

const createSignedXMLCallback = async (data: ISignedParam, callback: Function) => {
    const { pfxFile, password, xml } = data
    pem.readPkcs12(pfxFile, { p12Password: password }, (err, data) => {
        if (err) return callback(err, null)
        const certificate = data.cert
        const X509Certificate = certificate.substring(certificate.indexOf("\n") + 1, certificate.lastIndexOf("\n") + 1).replace(/\n/g, '');

        var sig = new SignedXml()
        sig.addReference(`//*[local-name(.)='Esign']`, ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"], "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true)
        //@ts-ignore
        sig.keyInfoProvider = {
            getKeyInfo: () => `<X509Data><X509SubjectName>1.2.840.113549.1.9.1=#16166e616d616e2e69636562656440676d61696c2e636f6d,CN=Digidocs Technologies,OU=ENGINEERING,O=DIGIDOCS TECHNOLOGIES PRIVATE LIMITED,L=PALAM,ST=DELHI,C=IN</X509SubjectName><X509Certificate>${X509Certificate}</X509Certificate></X509Data>`,
        }
        sig.signingKey = Buffer.from(data.key)
        sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        sig.computeSignature(xml)
        const xmlData = sig.getSignedXml()
        return callback(null, xmlData)
    })
}

const createSignedXML = util.promisify(createSignedXMLCallback)

export default createSignedXML