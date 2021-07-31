import pem from "pem";
import util from 'util'
import { SignedXml } from 'xml-crypto'
import { xml2json, json2xml } from './xmlParser'

interface ISignedParam {
    pfxFile: Buffer
    password: string
    xml: string
}

const splitString = (str: string, length: number) => {
    return str.match(new RegExp('.{1,' + length + '}', 'g'));
}

const createSignedXMLCallback = async (data: ISignedParam, callback: Function) => {
    const { pfxFile, password, xml } = data
    pem.readPkcs12(pfxFile, { p12Password: password }, (err, data) => {
        if (err) return callback(err, null)
        const certificate = data.cert
        const updatedCerti = certificate.substring(certificate.indexOf("\n") + 1, certificate.lastIndexOf("\n") + 1).replace(/\n/g, '');
        const X509Certificate = splitString(updatedCerti, 76)?.join(" ")

        var sig = new SignedXml()
        sig.addReference("//*[local-name(.)='Esign']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"], "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true)
        //@ts-ignore
        sig.keyInfoProvider = {
            getKeyInfo: () => `<X509Data><X509SubjectName>1.2.840.113549.1.9.1=#16166e616d616e2e69636562656440676d61696c2e636f6d,CN=Digidocs Technologies,OU=ENGINEERING,O=DIGIDOCS TECHNOLOGIES PRIVATE LIMITED,L=PALAM,ST=DELHI,C=IN</X509SubjectName><X509Certificate>${X509Certificate}</X509Certificate></X509Data>`,
        }
        sig.signingKey = Buffer.from(data.key)
        sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        sig.computeSignature(xml)
        const jsonData = JSON.parse(xml2json(sig.getSignedXml()))
        const updatedSignedValue = splitString(jsonData.Esign.Signature.SignatureValue._text, 76)?.join(" ")
        jsonData.Esign.Signature.SignatureValue._text = updatedSignedValue
        let xmlData = json2xml(jsonData)
        return callback(null, xmlData)
    })
}

const createSignedXML = util.promisify(createSignedXMLCallback)

export default createSignedXML