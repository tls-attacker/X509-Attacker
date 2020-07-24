/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 * <p>
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.signatureengine.keyparsers;

import de.rub.nds.signatureengine.SignatureEngine;
import org.apache.logging.log4j.LogManager;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;

public class PemUtil {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger();

    private PemUtil() {
    }

    public static void writePublicKey(PublicKey key, File targetFile) {
        PemObject pemObject = new PemObject("PublicKey", key.getEncoded());
        PemWriter pemWriter = null;
        try {
            pemWriter = new PemWriter(new FileWriter(targetFile));
            pemWriter.writeObject(pemObject);
        } catch (IOException ex) {
            LOGGER.warn(ex);
        } finally {
            try {
                pemWriter.close();
            } catch (IOException ex) {
                LOGGER.warn(ex);
            }
        }
    }

    public static void writeCertificate(Certificate cert, File file) {

        PemWriter pemWriter = null;
        try {
            pemWriter = new PemWriter(new FileWriter(file));
            for (org.bouncycastle.asn1.x509.Certificate tempCert : cert.getCertificateList()) {
                PemObject pemObject = new PemObject("CERTIFICATE", tempCert.getEncoded());
                pemWriter.writeObject(pemObject);
            }
            pemWriter.flush();
        } catch (IOException ex) {
            LOGGER.warn(ex);
        } finally {
            try {
                pemWriter.close();
            } catch (IOException ex) {
                LOGGER.warn(ex);
            }
        }
    }

    public static Certificate readCertificate(InputStream stream) throws FileNotFoundException, CertificateException,
            IOException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs = certFactory.generateCertificates(stream);
        java.security.cert.Certificate sunCert = (java.security.cert.Certificate) certs.toArray()[0];
        byte[] certBytes = sunCert.getEncoded();
        ASN1Primitive asn1Cert = TlsUtils.readASN1Object(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
        org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
        certs2[0] = cert;
        org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);
        return tlsCerts;
    }

    public static Certificate readCertificate(File f) throws FileNotFoundException, CertificateException, IOException {
        return readCertificate(new FileInputStream(f));
    }

    public static PrivateKey readPrivateKey(InputStream stream) throws IOException {
        PrivateKey privKey = null;
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        
        InputStreamReader reader = new InputStreamReader(stream);
         try (PEMParser parser = new PEMParser(reader)) {
            Object obj = null;
            while((obj = parser.readObject()) != null)
            {
                if (obj instanceof PEMKeyPair) {
                PEMKeyPair pair = (PEMKeyPair) obj;               
                privKey = converter.getPrivateKey(pair.getPrivateKeyInfo());
                }
                else if (obj instanceof PrivateKeyInfo) {
                    privKey = converter.getPrivateKey((PrivateKeyInfo) obj);
                }
            }
            
        } catch (Exception E) {
            throw new IOException("Could not read private key", E);
        } finally {
            stream.close();
            reader.close();
        }
        if(privKey == null)
        {
            throw new IOException("No private Key was found in key bytes");
        }
        return privKey;
    }

    public static PrivateKey readPrivateKey(File f) throws IOException {
        return readPrivateKey(new FileInputStream(f));
    }

    public static PublicKey readPublicKey(InputStream stream) throws IOException {
        PublicKey pubKey = null;
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        
        InputStreamReader reader = new InputStreamReader(stream);
         try (PEMParser parser = new PEMParser(reader)) {
            Object obj = null;
            while((obj = parser.readObject()) != null)
            {
                if (obj instanceof PEMKeyPair) {
                PEMKeyPair pair = (PEMKeyPair) obj;               
                pubKey = converter.getPublicKey(pair.getPublicKeyInfo());
                }
                else if (obj instanceof SubjectPublicKeyInfo) {
                    pubKey = converter.getPublicKey((SubjectPublicKeyInfo) obj);
                }
            }
            
        } catch (Exception E) {
            throw new IOException("Could not read public key", E);
        } finally {
            stream.close();
            reader.close();
        }
        if(pubKey == null)
        {
            throw new IOException("No public Key was found in key bytes");
        }
        return pubKey;
    }

    public static PublicKey readPublicKey(File f) throws IOException {
        return readPublicKey(new FileInputStream(f));
    }
    
    

    public static byte[] encodeCert(Certificate cert) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        cert.encode(stream);
        return stream.toByteArray();
    }
    
    public static KeyType getKeyType(File f) {        
        try {
            PrivateKey privKey = readPrivateKey(f);
            String algo = privKey.getAlgorithm();
            switch(algo){
                case "RSA":
                    return KeyType.RSA;
                case "DSA":
                    return KeyType.DSA;
                case "ECDSA":
                case "EC":
                    return KeyType.ECDSA;
                default:
                    LOGGER.warn("getKeyType(): no KeyType defined for: "+ algo);
                    return null;
        }
        } catch (IOException ex) {
            LOGGER.warn("getKeyType(): KeyType could not be recognized, IOException: "+ ex);
            return null;
        }
        
    }
            
        
}
