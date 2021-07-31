import convert from 'xml-js'

export const xml2json = (xml: string) => convert.xml2json(xml, { compact: true, spaces: 0 });
export const json2xml = (json: string) => convert.json2xml(json, { compact: true, spaces: 0 });

