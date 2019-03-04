package de.rub.nds.x509attacker.core.xmlparser;

import de.rub.nds.x509attacker.asn1.model.*;
import de.rub.nds.x509attacker.x509.model.meta.*;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.*;
import de.rub.nds.x509attacker.x509.model.x509asn1types.*;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.StringReader;

public class X509AttackerXmlParser {

    private JAXBContext jaxbContext = null;

    private X509CertificateList x509CertificateList = null;

    public X509AttackerXmlParser(final String xmlString) throws X509AttackerXmlParserException {
        this.createJaxbContext();
        this.unmarshal(xmlString);
    }

    public X509CertificateList getX509CertificateList() {
        return x509CertificateList;
    }

    private void createJaxbContext() throws X509AttackerXmlParserException {
        try {
            this.jaxbContext = JAXBContext.newInstance(
                    // ASN.1 model classes
                    Asn1AbstractField.class,
                    Asn1BitString.class,
                    Asn1BitString.Asn1BitStringItem.class,
                    Asn1Explicit.class,
                    Asn1Field.class,
                    Asn1Ia5String.class,
                    Asn1Ia5String.Asn1Ia5StringItem.class,
                    Asn1Integer.class,
                    Asn1Null.class,
                    Asn1ObjectIdentifier.class,
                    Asn1OctetString.class,
                    Asn1OctetString.Asn1OctetStringItem.class,
                    Asn1PrintableString.class,
                    Asn1PrintableString.Asn1PrintableStringItem.class,
                    Asn1RawField.class,
                    Asn1Sequence.class,
                    Asn1Set.class,
                    Asn1T61String.class,
                    Asn1T61String.Asn1T61StringItem.class,
                    Asn1UtcTime.class,
                    Asn1UtcTime.Asn1UtcTimeItem.class,

                    // X.509 model classes
                    X509Asn1BitString.class,
                    X509Asn1Ia5String.class,
                    X509Asn1Integer.class,
                    X509Asn1Null.class,
                    X509Asn1ObjectIdentifier.class,
                    X509Asn1OctetString.class,
                    X509Asn1PrintableString.class,
                    X509Asn1Sequence.class,
                    X509Asn1Set.class,
                    X509Asn1T61String.class,
                    X509Asn1UtcTime.class,

                    KeyInfo.class,
                    RealSignatureInfo.class,
                    Signature.class,
                    X509Certificate.class,
                    X509CertificateList.class,

                    // Todo: more x.509 model classes

                    AlgorithmIdentifier.class,
                    AttributeType.class,
                    AttributeTypeAndValue.class,
                    CertificateSerialNumber.class,
                    Extension.class,
                    Extensions.class,
                    RdnSequence.class,
                    RelativeDistinguishedName.class,
                    SubjectPublicKeyInfo.class,
                    TbsCertificate.class,
                    UniqueIdentifier.class,
                    Validity.class,
                    Version.class

                    // Todo: more x.509 model classes
            );
        } catch (JAXBException e) {
            throw new X509AttackerXmlParserException(e);
        }
    }

    private void unmarshal(final String xmlString) throws X509AttackerXmlParserException {
        try {
            StringReader stringReader = new StringReader(xmlString);
            Unmarshaller unmarshaller = this.jaxbContext.createUnmarshaller();
            Object unmarshalledObject = unmarshaller.unmarshal(stringReader);
            this.x509CertificateList = (X509CertificateList) unmarshalledObject;
        } catch (JAXBException e) {
            throw new X509AttackerXmlParserException(e);
        } catch (ClassCastException e) {
            throw new X509AttackerXmlParserException("XML root element MUST BE X509CertificateList!");
        }
    }
}
