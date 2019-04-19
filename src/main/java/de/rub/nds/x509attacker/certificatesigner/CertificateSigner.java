package de.rub.nds.x509attacker.certificatesigner;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.signatureengine.SignatureEngine;
import de.rub.nds.signatureengine.SignatureEngineException;
import de.rub.nds.x509.encoder.X509EncoderManager;
import de.rub.nds.x509.encoder.X509FieldEncoder;
import de.rub.nds.x509.model.*;
import de.rub.nds.x509.model.rfc5280.AlgorithmIdentifier;
import de.rub.nds.x509.model.rfc5280.TbsCertificate;
import de.rub.nds.x509.model.rfc5280.X509Certificate;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

public class CertificateSigner {

    private static final Logger LOGGER = LogManager.getLogger();

    private final X509CertificateList x509CertificateList;

    public CertificateSigner(final X509CertificateList x509CertificateList) {
        this.x509CertificateList = x509CertificateList;
    }

    public void signCertificates() throws CertificateSignerException {
        List<X509Certificate> x509Certificates = this.x509CertificateList.getCertificates();
        for (X509Certificate x509Certificate : x509Certificates) {
            this.signCertificate(x509Certificate);
        }
    }

    public void signCertificate(final X509Certificate x509Certificate) throws CertificateSignerException {
        this.encodeDataToBeSigned(x509Certificate);
        this.computeSignatureValues(x509Certificate);
        this.encodeCertificate(x509Certificate);
    }

    private void encodeDataToBeSigned(final X509Certificate x509Certificate) throws CertificateSignerException {
        TbsCertificate tbsCertificate = this.findTbsCertificate(x509Certificate);
        byte[] toBeSigned = new byte[0];
        if (tbsCertificate != null) {
            toBeSigned = X509EncoderManager.encodeForSignature(tbsCertificate);
        }
        x509Certificate.setToBeSignedBytes(toBeSigned);
    }

    private TbsCertificate findTbsCertificate(final X509Certificate x509Certificate) throws CertificateSignerException {
        TbsCertificate result = null;
        int tbsCertificateCount = 0;
        for (Asn1Encodable asn1Encodable : x509Certificate.getFields()) {
            if (asn1Encodable instanceof TbsCertificate) {
                result = (TbsCertificate) asn1Encodable;
                tbsCertificateCount++;
            }
        }
        if (tbsCertificateCount > 1) {
            throw new CertificateSignerException("X509Certificate must not contain more than one element of type TbsCertificate!");
        }
        return result;
    }

    private void computeSignatureValues(final X509Certificate x509Certificate) throws CertificateSignerException {
        List<Asn1Encodable> asn1Encodables = x509Certificate.getFields();
        byte[] toBeSigned = x509Certificate.getToBeSignedBytes();
        for (Asn1Encodable asn1Encodable : asn1Encodables) {
            if (asn1Encodable instanceof SignatureAlgorithm) {
                this.createSignatureAlgorithm((SignatureAlgorithm) asn1Encodable);
            }
            if (asn1Encodable instanceof SignatureValue) {
                this.createSignatureValue((SignatureValue) asn1Encodable, toBeSigned);
            }
        }
    }

    private void createSignatureAlgorithm(final SignatureAlgorithm signatureAlgorithm) throws CertificateSignerException {
        RealSignatureInfo realSignatureInfo = signatureAlgorithm.getReferencedRealSignatureInfo();
        if (realSignatureInfo != null) {
            AlgorithmIdentifier realSignatureInfoAlgorithmIdentifier = realSignatureInfo.getAlgorithmIdentifier();
            signatureAlgorithm.clearFields();
            signatureAlgorithm.addFields(realSignatureInfoAlgorithmIdentifier.getFields());
        }
    }

    private void createSignatureValue(final SignatureValue signatureValue, final byte[] toBeSigned) throws CertificateSignerException {
        try {
            RealSignatureInfo realSignatureInfo = signatureValue.getReferencedRealSignatureInfo();
            if (realSignatureInfo != null) {
                AlgorithmIdentifier realSignatureInfoAlgorithmIdentifier = realSignatureInfo.getAlgorithmIdentifier();
                KeyInfo keyInfo = realSignatureInfo.getKeyInfo();
                String objectIdentifier = this.retrieveObjectIdentifier(realSignatureInfoAlgorithmIdentifier);
                Asn1Field parameters = this.retrieveParameters(realSignatureInfoAlgorithmIdentifier);
                byte[] keyBytes = this.retrieveKeyBytes(keyInfo);
                byte[] signatureBytes = this.computeSignature(objectIdentifier, keyBytes, parameters, toBeSigned);
                Asn1PrimitiveBitString signatureBitString = new Asn1PrimitiveBitString();
                signatureBitString.setBitStringValue(signatureBytes);
                signatureValue.setAsn1Encodable(signatureBitString);
            }
        } catch (ClassCastException e) {
            throw new CertificateSignerException(e);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new CertificateSignerException(e);
        } catch (SignatureEngineException e) {
            throw new CertificateSignerException(e);
        }
    }

    private String retrieveObjectIdentifier(final AlgorithmIdentifier algorithmIdentifier) throws ClassCastException, ArrayIndexOutOfBoundsException {
        Asn1ObjectIdentifier objectIdentifier = (Asn1ObjectIdentifier) algorithmIdentifier.getFields().get(0);
        return objectIdentifier.getObjectIdentifierValue();
    }

    private Asn1Field retrieveParameters(final AlgorithmIdentifier algorithmIdentifier) throws ClassCastException, ArrayIndexOutOfBoundsException {
        return (Asn1Field) algorithmIdentifier.getFields().get(1);
    }

    private byte[] retrieveKeyBytes(final KeyInfo keyInfo) throws CertificateSignerException {
        if (keyInfo != null) {
            try {
                String keyFileName = keyInfo.getKeyFile();
                if (keyInfo.getReferencedX509Certificate() != null) {
                    keyFileName = keyInfo.getReferencedX509Certificate().getKeyFile();
                }
                KeyFileManager keyFileManager = KeyFileManager.getReference();
                return keyFileManager.getKeyFileContent(keyFileName);
            } catch (KeyFileManagerException e) {
                throw new CertificateSignerException(e);
            }
        } else {
            throw new CertificateSignerException("RealSignatureInfo has to specify key material. This is done by creating an instance of KeyInfo and setting it to the RealSignatureInfo instance!");
        }
    }

    private byte[] computeSignature(final String objectIdentifier, final byte[] keyBytes, final Asn1Field parameters, final byte[] toBeSigned) throws SignatureEngineException {
        SignatureEngine signatureEngine = SignatureEngine.getInstance(objectIdentifier);
        signatureEngine.init(keyBytes, SignatureEngine.KeyType.PEM_ENCODED, parameters.getEncoder().encode());
        return signatureEngine.sign(toBeSigned);
    }

    private void encodeCertificate(final X509Certificate x509Certificate) {
        byte[] encodedCertificate = X509EncoderManager.encodeForCertificate(x509Certificate);
        x509Certificate.setSignedCertificateBytes(encodedCertificate);
    }
}
