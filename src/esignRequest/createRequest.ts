import pem from "pem";
import util from 'util'
import { SignedXml } from 'xml-crypto'
import { xml2json, json2xml } from './xmlParser'
import fs from 'fs'

interface ISignedParam {
    pfxFile: Buffer
    password: string
    xml: string
}

const createSignedXMLCallback = async (data: ISignedParam, callback: Function) => {
    const { pfxFile, password, xml } = data
    pem.readPkcs12(pfxFile, { p12Password: password }, (err, data) => {
        if (err) throw err
        const certificate = data.cert
        const X509Certificate = certificate.substring(certificate.indexOf("\n") + 1, certificate.lastIndexOf("\n") + 1).replace(/\n/g, '');

        var sig = new SignedXml()
        sig.addReference("//*[local-name(.)='Docs']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"])
        //@ts-ignore
        sig.keyInfoProvider = {
            getKeyInfo: () => `<X509Data><X509SubjectName/><X509Certificate>${X509Certificate}</X509Certificate></X509Data>`,
        }
        sig.signingKey = Buffer.from(data.key)
        sig.computeSignature(xml)
        let jsonFile = JSON.parse(xml2json(sig.getSignedXml()))
        jsonFile._declaration._attributes.encoding = "UTF-8"
        jsonFile.Esign.Docs._attributes = {}
        jsonFile.Esign.Signature.SignedInfo.Reference._attributes.URI = ""
        let xmlFile = json2xml(jsonFile)
        return callback(xmlFile)
    })
}

const createSignedXML = util.promisify(createSignedXMLCallback)

export default createSignedXML