/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.signatureengine.keyparsers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class PemUtil {

    private PemUtil() {}

    public static void writePublicKey(PublicKey key, File targetFile) {
        PemObject pemObject = new PemObject("PublicKey", key.getEncoded());
        PemWriter pemWriter = null;
        try {
            pemWriter = new PemWriter(new FileWriter(targetFile));
            pemWriter.writeObject(pemObject);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            try {
                if (pemWriter != null) {
                    pemWriter.close();
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    public static void writeCertificate(Certificate cert, File file) {

        PemWriter pemWriter = null;
        try {
            pemWriter = new PemWriter(new FileWriter(file));
            for (TlsCertificate tempCert : cert.getCertificateList()) {
                PemObject pemObject = new PemObject("CERTIFICATE", tempCert.getEncoded());
                pemWriter.writeObject(pemObject);
            }
            pemWriter.flush();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            try {
                if (pemWriter != null) {
                    pemWriter.close();
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    public static Certificate readCertificate(InputStream stream)
            throws FileNotFoundException, CertificateException, IOException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs =
                certFactory.generateCertificates(stream);
        java.security.cert.Certificate sunCert =
                (java.security.cert.Certificate) certs.toArray()[0];
        byte[] certBytes = sunCert.getEncoded();
        TlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        TlsCertificate tlsCertificate = crypto.createCertificate(certBytes);
        return new Certificate(new TlsCertificate[] {tlsCertificate});
    }

    public static Certificate readCertificate(File file)
            throws FileNotFoundException, CertificateException, IOException {
        return readCertificate(new FileInputStream(file));
    }

    public static PrivateKey readPrivateKey(InputStream stream) {
        PrivateKey privKey;
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

        InputStreamReader reader = new InputStreamReader(stream);
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj = null;
            while ((obj = parser.readObject()) != null) {
                if (obj instanceof PEMKeyPair) {
                    PEMKeyPair pair = (PEMKeyPair) obj;
                    privKey = converter.getPrivateKey(pair.getPrivateKeyInfo());
                    return privKey;
                } else if (obj instanceof PrivateKeyInfo) {
                    privKey = converter.getPrivateKey((PrivateKeyInfo) obj);
                    return privKey;
                }
            }
            PrivateKeyInfo privKeyInfo = (PrivateKeyInfo) obj;
            return converter.getPrivateKey(privKeyInfo);
        } catch (Exception e) {
            throw new RuntimeException("Could not read private key", e);
        } finally {
            try {
                stream.close();
                reader.close();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    public static PrivateKey readPrivateKey(File file) {
        try {
            return readPrivateKey(new FileInputStream(file));
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static PublicKey readPublicKey(InputStream stream) {
        PublicKey pubKey;
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

        InputStreamReader reader = new InputStreamReader(stream);
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj = null;
            while ((obj = parser.readObject()) != null) {
                if (obj instanceof PEMKeyPair) {
                    PEMKeyPair pair = (PEMKeyPair) obj;
                    pubKey = converter.getPublicKey(pair.getPublicKeyInfo());
                    return pubKey;
                } else if (obj instanceof SubjectPublicKeyInfo) {
                    pubKey = converter.getPublicKey((SubjectPublicKeyInfo) obj);
                    return pubKey;
                }
            }
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) obj;
            return converter.getPublicKey(publicKeyInfo);
        } catch (Exception e) {
            throw new RuntimeException("Could not read public key", e);
        } finally {
            try {
                stream.close();
                reader.close();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    public static PublicKey readPublicKey(File file) {
        try {
            return readPublicKey(new FileInputStream(file));
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        }
    }
}
