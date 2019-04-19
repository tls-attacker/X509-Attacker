package de.rub.nds.x509attacker.xmlparser;

import de.rub.nds.asn1.adapter.BigIntegerAdapter;
import de.rub.nds.asn1.model.*;
import de.rub.nds.modifiablevariable.biginteger.*;
import de.rub.nds.modifiablevariable.bool.BooleanExplicitValueModification;
import de.rub.nds.modifiablevariable.bool.BooleanToogleModification;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.*;
import de.rub.nds.modifiablevariable.integer.*;
import de.rub.nds.modifiablevariable.mlong.*;
import de.rub.nds.modifiablevariable.singlebyte.*;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.string.StringExplicitValueModification;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.x509.model.*;
import de.rub.nds.x509.model.asn1.*;
import de.rub.nds.x509.model.rfc5280.*;

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
                    // ModifiableVariables
                    ModifiableBigInteger.class,
                    BigIntegerAddModification.class,
                    BigIntegerExplicitValueModification.class,
                    BigIntegerInteractiveModification.class,
                    BigIntegerShiftLeftModification.class,
                    BigIntegerShiftRightModification.class,
                    BigIntegerSubtractModification.class,
                    BigIntegerXorModification.class,

                    ModifiableBoolean.class,
                    BooleanExplicitValueModification.class,
                    BooleanToogleModification.class,

                    ModifiableByteArray.class,
                    ByteArrayDeleteModification.class,
                    ByteArrayDuplicateModification.class,
                    ByteArrayExplicitValueModification.class,
                    ByteArrayInsertModification.class,
                    ByteArrayPayloadModification.class,
                    ByteArrayShuffleModification.class,
                    ByteArrayXorModification.class,

                    ModifiableInteger.class,
                    IntegerAddModification.class,
                    IntegerExplicitValueModification.class,
                    IntegerShiftLeftModification.class,
                    IntegerShiftRightModification.class,
                    IntegerSubtractModification.class,
                    IntegerXorModification.class,

                    ModifiableLong.class,
                    LongAddModification.class,
                    LongExplicitValueModification.class,
                    LongSubtractModification.class,
                    LongXorModification.class,

                    ModifiableByte.class,
                    ByteAddModification.class,
                    ByteExplicitValueModification.class,
                    ByteSubtractModification.class,
                    ByteXorModification.class,

                    ModifiableString.class,
                    StringExplicitValueModification.class,

                    // ASN.1 model classes
                    Asn1Boolean.class,
                    Asn1ConstructedBitString.class,
                    Asn1ConstructedIa5String.class,
                    Asn1ConstructedOctetString.class,
                    Asn1ConstructedPrintableString.class,
                    Asn1ConstructedT61String.class,
                    Asn1ConstructedUtcTime.class,
                    Asn1ConstructedUtf8String.class,
                    Asn1EncapsulatingBitString.class,
                    Asn1EncapsulatingOctetString.class,
                    Asn1Explicit.class,
                    Asn1Field.class,
                    Asn1Implicit.class,
                    Asn1Integer.class,
                    Asn1Null.class,
                    Asn1ObjectIdentifier.class,
                    Asn1PrimitiveBitString.class,
                    Asn1PrimitiveIa5String.class,
                    Asn1PrimitiveOctetString.class,
                    Asn1PrimitivePrintableString.class,
                    Asn1PrimitiveT61String.class,
                    Asn1PrimitiveUtcTime.class,
                    Asn1PrimitiveUtf8String.class,
                    Asn1Sequence.class,
                    Asn1Set.class,

                    // X.509 ASN.1 model classes
                    X509Asn1BitString.class,
                    X509Asn1Boolean.class,
                    X509Asn1Choice.class,
                    X509Asn1ConstructedBitString.class,
                    X509Asn1ConstructedIa5String.class,
                    X509Asn1ConstructedOctetString.class,
                    X509Asn1ConstructedPrintableString.class,
                    X509Asn1ConstructedT61String.class,
                    X509Asn1ConstructedUtcTime.class,
                    X509Asn1ConstructedUtf8String.class,
                    X509Asn1EncapsulatingBitString.class,
                    X509Asn1EncapsulatingOctetString.class,
                    X509Asn1Ia5String.class,
                    X509Asn1Integer.class,
                    X509Asn1Null.class,
                    X509Asn1ObjectIdentifier.class,
                    X509Asn1OctetString.class,
                    X509Asn1PrimitiveBitString.class,
                    X509Asn1PrimitiveIa5String.class,
                    X509Asn1PrimitiveOctetString.class,
                    X509Asn1PrimitivePrintableString.class,
                    X509Asn1PrimitiveT61String.class,
                    X509Asn1PrimitiveUtcTime.class,
                    X509Asn1PrimitiveUtf8String.class,

                    // X.509 model classes
                    KeyInfo.class,
                    RealSignatureInfo.class,
                    SignatureAlgorithm.class,
                    SignatureValue.class,
                    X509CertificateList.class,

                    // X.509 RFC 5280 model classes
                    AlgorithmIdentifier.class,
                    AttributeType.class,
                    AttributeTypeAndValue.class,
                    AttributeValue.class,
                    CertificateSerialNumber.class,
                    DirectoryString.class,
                    Extension.class,
                    Extensions.class,
                    Name.class,
                    RdnSequence.class,
                    RelativeDistinguishedName.class,
                    SubjectPublicKeyInfo.class,
                    TbsCertificate.class,
                    Time.class,
                    UniqueIdentifier.class,
                    Validity.class,
                    Version.class,
                    X509Certificate.class

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
            unmarshaller.setAdapter(new ByteArrayAdapter());
            unmarshaller.setAdapter(new BigIntegerAdapter());
            Object unmarshalledObject = unmarshaller.unmarshal(stringReader);
            this.x509CertificateList = (X509CertificateList) unmarshalledObject;
        } catch (JAXBException e) {
            throw new X509AttackerXmlParserException(e);
        } catch (ClassCastException e) {
            throw new X509AttackerXmlParserException("XML root element MUST BE X509CertificateList!");
        } catch(IllegalArgumentException e) {
            throw new X509AttackerXmlParserException("Illegal Argument exception: " + e.getMessage() + "! Did you forget <sequenceElements> tag?");
        }
    }
}
