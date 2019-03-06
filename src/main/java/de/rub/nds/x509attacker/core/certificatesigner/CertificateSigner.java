package de.rub.nds.x509attacker.core.certificatesigner;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.signatureengine.SignatureEngine;
import de.rub.nds.x509attacker.signatureengine.SignatureEngineException;
import de.rub.nds.x509attacker.x509.encoder.EncodeMode;
import de.rub.nds.x509attacker.x509.encoder.X509Encoder;
import de.rub.nds.x509attacker.x509.model.nonasn1.KeyInfo;
import de.rub.nds.x509attacker.x509.model.nonasn1.RealSignatureInfo;
import de.rub.nds.x509attacker.x509.model.nonasn1.X509CertificateList;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.AlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.Signature;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.X509Certificate;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1BitString;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1ObjectIdentifier;

import java.util.List;

public class CertificateSigner {

    private CertificateSigner() {

    }

    public static void signAllCertificates(X509CertificateList certificateList) throws CertificateSignerException {
        for (X509Certificate certificate : certificateList.getCertificates()) {
            signCertificate(certificate);
        }
    }

    public static void signCertificate(X509Certificate certificate) throws CertificateSignerException {
        List<Signature> signatures = certificate.findAllFields(Signature.class);
        byte[] toBeSigned = encodeCertificateForSignature(certificate);
        certificate.setToBeSigned(toBeSigned);
        for (Signature signature : signatures) {
            computeSingleSignatureValue(toBeSigned, signature);
        }
        updateSignedCertificate(certificate);
    }

    private static byte[] encodeCertificateForSignature(final X509Certificate certificate) {
        X509Encoder x509Encoder = X509Encoder.getReference();
        x509Encoder.setEncodeMode(EncodeMode.SIGNATURE);
        return x509Encoder.encode(certificate);
    }

    private static void computeSingleSignatureValue(final byte[] toBeSigned, final Signature signature) throws CertificateSignerException {
        RealSignatureInfo realSignatureInfo = signature.getRealSignatureInfo();
        SignatureEngine signatureEngine = null;
        if (realSignatureInfo != null) {
            signatureEngine = initializeSignatureEngine(realSignatureInfo);
            try {
                String algorithmIdentifier = signatureEngine.retrieveObjectIdentifier();
                byte[] signatureValue = signatureEngine.sign(toBeSigned);
                updateSignature(signature, algorithmIdentifier, signatureValue);
            } catch (SignatureEngineException e) {
                throw new CertificateSignerException(e);
            }
        }
    }

    private static SignatureEngine initializeSignatureEngine(final RealSignatureInfo realSignatureInfo) throws CertificateSignerException {
        SignatureEngine signatureEngine = null;
        AlgorithmIdentifier algorithmIdentifier = realSignatureInfo.getSignatureAlgorithm();
        KeyInfo keyInfo = realSignatureInfo.getKeyInfo();
        if (algorithmIdentifier != null && keyInfo != null) {
            X509Asn1ObjectIdentifier objectIdentifier = algorithmIdentifier.findField(X509Asn1ObjectIdentifier.class);
            Asn1RawField parameters = algorithmIdentifier.getFieldAtPos(1);
            if (objectIdentifier != null) {
                String objectIdentifierString = objectIdentifier.getAsn1ObjectIdentifierValue();
                byte[] keyFileContent = retrieveKeyFileContent(keyInfo);
                byte[] encodedParameters = (parameters != null) ? parameters.encode() : null;
                try {
                    signatureEngine = SignatureEngine.getInstance(objectIdentifierString);
                    signatureEngine.init(keyFileContent, SignatureEngine.KeyType.PEM_ENCODED, encodedParameters);
                } catch (SignatureEngineException e) {
                    throw new CertificateSignerException(e);
                }
            }
        } else {
            throw new CertificateSignerException("RealSignatureInfo must contain an AlgorithmIdentifier and KeyInfo! Otherwise, signature computation is not possible!");
        }
        return signatureEngine;
    }

    private static byte[] retrieveKeyFileContent(final KeyInfo keyInfo) throws CertificateSignerException {
        byte[] keyFileContent = null;
        int keyFileId = keyInfo.getKeyFileId();
        if (keyFileId != 0) {
            KeyFileManager keyFileManager = KeyFileManager.getReference();
            try {
                keyFileContent = keyFileManager.getKeyFile(keyFileId).keyFileContent;
            } catch (KeyFileManagerException e) {
                throw new CertificateSignerException(e);
            }
        } else {
            throw new CertificateSignerException("Key file content is not available!");
        }
        return keyFileContent;
    }

    private static void updateSignature(final Signature signature, final String algorithmIdentifier, final byte[] signatureValue) {
        X509Asn1ObjectIdentifier asn1AlgorithmIdentifier = new X509Asn1ObjectIdentifier();
        asn1AlgorithmIdentifier.setAsn1ObjectIdentifierValue(algorithmIdentifier);
        X509Asn1BitString asn1BitString = new X509Asn1BitString();
        X509Asn1BitString.Asn1BitStringItem asn1BitStringItem = new X509Asn1BitString.Asn1BitStringItem();
        asn1BitStringItem.setAsn1NumberOfUnusedBits(0);
        asn1BitStringItem.setAsn1BitStringValue(signatureValue);
        asn1BitString.addValue(asn1BitStringItem);
        signature.setAlgorithmIdentifier(asn1AlgorithmIdentifier);
        signature.setSignatureValue(asn1BitString);
    }

    private static void updateSignedCertificate(final X509Certificate certificate) {
        byte[] encodedCertificate = encodeCertificateForCertificate(certificate);
        certificate.setGeneratedCertificate(encodedCertificate);
    }

    private static byte[] encodeCertificateForCertificate(final X509Certificate certificate) {
        X509Encoder x509Encoder = X509Encoder.getReference();
        x509Encoder.setEncodeMode(EncodeMode.CERTIFICATE);
        return x509Encoder.encode(certificate);
    }
}
