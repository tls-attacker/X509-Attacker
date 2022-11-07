/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.x509attacker.X509Attributes;
import de.rub.nds.x509attacker.filesystem.CertificateFileWriter;
import de.rub.nds.x509attacker.identifiermap.IdentifierMap;
import de.rub.nds.x509attacker.linker.Linker;
import de.rub.nds.x509attacker.x509.serializer.X509CertificateSerializer;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngine;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngineException;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represent one X509Certificate with the certificate itself as an Asn1 structure, a SignatureInfo with Information how
 * the signature of the certificate is computed, and a KeyInfo Element containing the KeyFile of the certificate.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Certificate {

    private static final Logger LOGGER = LogManager.getLogger(X509Certificate.class);

    @HoldsModifiableVariable
    private Asn1Sequence certificate;

    private SignatureInfo signatureInfo;

    private KeyInfo keyInfo;

    /**
     * Converts the intermediateAsn1Field structure of a parsed Certificate into one X509Certificate object
     *
     *
     * @param  intermediateAsn1Fields
     *                                A List of IntermediateAsn1Field containing a parsed Intermediate Asn1 Structure of
     *                                a certificate
     * @return                        an X509Certificate constructed from the asn1 fields
     *
     */
    public static X509Certificate getInstance(List<IntermediateAsn1Field> intermediateAsn1Fields) {
        return new X509Certificate(intermediateAsn1Fields);
    }

    /**
     * Converts the intermediateAsn1Field structure of a parsed Certificate into one X509Certificate object Expects a
     * correct defined intermediate strucutre of a certificate. Create corresponding SignatureInfo and KeyInfo Elements.
     *
     * @param intermediateAsn1Fields
     *                               A List<IntermediateAsn1Field> containing a parsed Intermediate Asn1 Structure of a
     *                               certificate
     *
     */
    private X509Certificate(List<IntermediateAsn1Field> intermediateAsn1Fields) {

        // create certificate
        if (intermediateAsn1Fields.size() == 1) {
            certificate = Certificate.getInstance(intermediateAsn1Fields.get(0), "certificate").asn1;
        }

        // Set Default Attribute "Attach to Certificate List" to true
        certificate.setAttribute(X509Attributes.ATTACH_TO_CERTIFICATE_LIST, "true");

        // creates default SignatureInfo
        signatureInfo = new SignatureInfo();
        signatureInfo.setToBeSignedIdentifiers(Arrays.asList("/certificate/tbsCertificate"));
        signatureInfo.setSignatureValueTargetIdentifier("/certificate/signatureValue");
        signatureInfo.setKeyInfoIdentifier("");
        signatureInfo.setSignatureAlgorithmOidIdentifier("/certificate/signatureAlgorithm/algorithm");
        signatureInfo.setParametersIdentifier("/certificate/signatureAlgorithm/parameters");
        signatureInfo.setIdentifier("signatureInfo");
        signatureInfo.setType("SignatureInfo");

        // creates default KeyInfo
        keyInfo = new KeyInfo();
        keyInfo.setKeyFileName("");
        keyInfo.setIdentifier("keyInfo");
        keyInfo.setType("KeyInfo");

        // connect tbsCertificate/SubjectPublicKeyInfo with KeyInfo Object for automatic encoding of the correct key
        // if this is not set, the SubjectPublicKeyInfo must be set correctly manually
        Asn1Encodable asn1Enc =
            this.getIdentifierMap().getElementByIDPath("/certificate/tbsCertificate/subjectPublicKeyInfo");
        asn1Enc.setAttribute("fromIdentifier", "/keyInfo");

        // randomize the subject cn name, such that no two randomly choosen certificate have the same subject
        // this prevents self signing certificates within the chain
        // and that SSL libraries confuse the certificate with the original certificates
        // (for example OpenSSL: To build the chain it will first look and take the certificate in the OS library of
        // trusted CA certificates
        // which will leads to usage of a wrong key)
        UUID guid = java.util.UUID.randomUUID();
        List<String> attributeTypeAndValuePathList = this.getIdentifierMap().getIDPathsByType("AttributeTypeAndValue");

        for (String path : attributeTypeAndValuePathList.stream().filter(s -> s.contains("subject"))
            .collect(Collectors.toList())) {
            if (((Asn1ObjectIdentifier) this.getIdentifierMap().getElementByIDPath(path + "/type")).getValue()
                .equals("2.5.4.3")) {
                byte[] guidBytes = guid.toString().split("-")[0].getBytes();
                ((Asn1Field) this.getIdentifierMap().getElementByIDPath(path + "/value")).getContent()
                    .setModification(new ByteArrayExplicitValueModification(guidBytes));
            }
        }

    }

    public X509Certificate() {
    }

    /**
     * Returns a List of the Asn1Encodables of the certificate. Containing the certificate, signatureInfo and KeyInfo
     * structure.
     *
     * An important structure for many old codesnippets. It needs to contain the certificate, signatureInfo and keyInfo
     * Objects.
     *
     * @return A List of Ans1Encdoable of certificate, signatureInfo and keyInfo.
     *
     */
    public List<Asn1Encodable> getAsn1Encodables() {
        return getAsn1Encodables(false);
    }

    /**
     * Returns a List of the Asn1Encodables of the certificate. An important structure for many old codesnippets. It
     * needs to contain the certificate, signatureInfo and keyInfo Objects.
     *
     * @param  certificateOnly
     *                         Flag whether the List of Asn1Encodable only contains the certificate or certificate,
     *                         signatureInfo, keyInfos
     * @return                 A List of Asn1Encodable of certificate, signatureInfo and keyInfo.
     *
     */
    public List<Asn1Encodable> getAsn1Encodables(boolean certificateOnly) {
        List<Asn1Encodable> asn1Encodables = new LinkedList<>();
        if (certificateOnly) {
            asn1Encodables.add(certificate);
        } else {
            asn1Encodables.add(certificate);
            asn1Encodables.add(signatureInfo);
            asn1Encodables.add(keyInfo);
        }

        return asn1Encodables;
    }

    /**
     * Creates and returns the currently correct IdentifierMap. A Hashmap containing each path of identifiers and the
     * corresponding Asn1Element. Containing the certificate, signatureInfo and KeyInfo structure.
     *
     * @return The IdentifierMap of the X509Certificate.
     *
     */
    public final IdentifierMap getIdentifierMap() {
        return new IdentifierMap(getAsn1Encodables());
    }

    /**
     * Creates and returns the currently correct IdentifierMap. A Hashmap containing each path of identifiers and the
     * corresponding Asn1Element
     *
     * @param  certificateOnly
     *                         Flag whether the IdentifierMap only contains the certificate or certificate,
     *                         signatureInfo, keyInfos
     * @return                 The IdentifierMap of the X509Certificate.
     *
     */
    public final IdentifierMap getIdentifierMap(boolean certificateOnly) {
        return new IdentifierMap(getAsn1Encodables(certificateOnly));
    }

    /**
     * Creates and returns the currently correct Linker. A map containing all links between two Asn1 Elements. A link is
     * defined with an Asn1 Attribute and allows to reuse an Asn1 Element at a different position inside the ASN1
     * structure.
     *
     * @return The Linker of the X509Certificate.
     *
     */
    public Linker getLinker() {
        return new Linker(getIdentifierMap().getMap());
    }

    public SignatureInfo getSignatureInfo() {
        return signatureInfo;
    }

    public void setSignatureInfo(SignatureInfo signatureInfo) {
        this.signatureInfo = signatureInfo;
    }

    public KeyInfo getKeyInfo() {
        return keyInfo;
    }

    public void setKeyInfo(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public void setKeyFile(File keyFile) throws IOException {
        this.keyInfo.setKeyFile(keyFile);
    }

    public Asn1Sequence getCertificate() {
        return certificate;
    }

    /**
     * Write the X509Certificate as certificateFile in .pem format to the given directory/filename.
     *
     *
     *
     * @param  directory
     *                   The path to the directory.
     * @param  filename
     *                   The filename of the certificateFile (without .pem).
     * @return           The full path of the written certificate
     *
     */
    public File writeCertificate(String directory, String filename) {
        try {
            String certificateFileName = filename + ".pem";
            CertificateFileWriter certificateFileWriter = new CertificateFileWriter(directory, certificateFileName);
            certificateFileWriter.writeCertificate(getEncodedCertificate());
            certificateFileWriter.close();
            return new File(directory + "/" + certificateFileName);
        } catch (IOException e) {

            LOGGER.warn("Error writing Certificate to PEM: " + e);
        }
        return null;
    }

    /**
     * Computes and returns a byte Array of the encoded form of the X509Certificate
     *
     *
     * @return The byte Array of the encoded certificate.
     *
     */
    public byte[] getEncodedCertificate() {
        byte[] encodedCertificate;
        encodedCertificate = Asn1EncoderForX509.encodeForCertificate(getLinker(), getAsn1Encodables());
        return encodedCertificate;
    }

    /**
     * Computes and set the signature of the Certificate. For the computation it takes the SignatureInfo of the
     * X509Certificate into consideration for information about which structure should be signed(default:
     * /certificate/tbsCertificate), which AlgorithmOID and Parameters are used (default: the Infos defined in
     * /certificate/signatureAlgorithm/) and the target where to write the computed signature value (default:
     * /certificate/tbsCertificate/signatureValue). The used private Key is defined in the parameter KeyInfo
     *
     * @param key
     *            The KeyInfo which is used for the computation
     *
     */
    public void signCertificate(KeyInfo key) throws XmlSignatureEngineException {
        XmlSignatureEngine xmlSignatureEngine = new XmlSignatureEngine(getLinker(), getIdentifierMap().getMap());
        xmlSignatureEngine.computeSignature(key);
    }

    /**
     * Returns a deep copy of this X509Certificate
     *
     * @return                                     a deep Copy of this X509certificate.
     * @throws jakarta.xml.bind.JAXBException
     *                                             If a copy could not be created
     * @throws java.io.IOException
     *                                             If a copy could not be created
     * @throws javax.xml.stream.XMLStreamException
     *                                             If a copy could not be created
     */
    public X509Certificate getCopy() throws JAXBException, IOException, XMLStreamException {
        return X509CertificateSerializer.copyX509Certificate(this);
    }

    /**
     * Returns the effective Signature OID which is used for the computation of the certificate signature.
     *
     * it will first look into the signatureInfo object for a specific defined AlgoOID and then into the Path inside the
     * certificate
     *
     * @return a OID String representing the effective Signature Algorithm.
     */
    public String getEffectiveSignatureOID() {
        String signatureOID = signatureInfo.getSignatureAlgorithmOidValue();
        if (signatureOID == null || signatureOID.isEmpty()) {
            try {
                Asn1ObjectIdentifier asn1ObjectIdentifier = (Asn1ObjectIdentifier) getIdentifierMap()
                    .getElementByIDPath(signatureInfo.getSignatureAlgorithmOidIdentifier().trim());
                signatureOID = asn1ObjectIdentifier.getValue();
            } catch (Throwable e) {
                LOGGER.warn("getEffectiveSignatureOID(): could not recognize the effective SignatureOID: " + e);
                return null;
            }
        }
        return signatureOID.trim();
    }

}
