/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.X509Attributes;
import de.rub.nds.x509attacker.filesystem.CertificateFileWriter;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.linker.Linker;
import de.rub.nds.x509attacker.x509.X509Certificate;
import java.io.IOException;
import java.util.List;

public class X509Encoder {

    private final X509Certificate certificate;

    private final String certificateOutputDirectory;

    private final String keyDirectory;

    public X509Encoder(X509Certificate certificate, String certificateOutputDirectory, String keyDirectory) {
        this.certificate = certificate;
        this.certificateOutputDirectory = certificateOutputDirectory;
        this.keyDirectory = keyDirectory;
        Registry.getInstanceAndRegisterAll();
    }

    public void encode() {
        try {

            // Create links
            Linker linker = certificate.getLinker();

            // Load key files
            KeyFileManager keyFileManager = KeyFileManager.getReference();
            keyFileManager.init(keyDirectory);

            // Create signatures
            // XmlSignatureEngine xmlSignatureEngine = new XmlSignatureEngine(linker,
            // certificate.getIdentifierMap().getMap());
            // xmlSignatureEngine.computeSignatures();

            // Encode XML for certificate
            List<Asn1Encodable> certificates = certificate.getAsn1Encodables();
            byte[][] encodedCertificates = new byte[certificates.size()][];
            for (int i = 0; i < certificates.size(); i++) {
                encodedCertificates[i] = Asn1EncoderForX509.encodeForCertificate(linker, certificates.get(i));
            }

            // Write certificate files
            writeCertificates(certificateOutputDirectory, certificates, encodedCertificates);

            System.out.println("Done.");
        } catch (KeyFileManagerException | IOException e) {
            e.printStackTrace();
        }

    }

    private void writeCertificates(final String certificateOutputDirectory, final List<Asn1Encodable> certificates,
        final byte[][] encodedCertificates) throws IOException {
        CertificateFileWriter certificateChainFileWriter =
            new CertificateFileWriter(certificateOutputDirectory, "certificate_chain.pem");
        for (int i = 0; i < certificates.size(); i++) {
            Asn1Encodable certificate = certificates.get(i);
            if (certificate.getType().equalsIgnoreCase("Certificate") == false) {
                continue;
            }
            // Append certificate to certificate chain file
            if (de.rub.nds.asn1.util.AttributeParser.parseBooleanAttributeOrDefault(certificate,
                X509Attributes.ATTACH_TO_CERTIFICATE_LIST, false)) {
                certificateChainFileWriter.writeCertificate(encodedCertificates[i]);
            }
            // Write certificate in its own file
            writeSingleCertificate(certificateOutputDirectory, certificate, encodedCertificates[i]);
        }
        certificateChainFileWriter.close();
    }

    private void writeSingleCertificate(final String certificateOutputDirectory, final Asn1Encodable certificate,
        final byte[] encodedCertificate) throws IOException {
        String certificateFileName = certificate.getIdentifier() + ".pem";
        CertificateFileWriter certificateFileWriter =
            new CertificateFileWriter(certificateOutputDirectory, certificateFileName);
        certificateFileWriter.writeCertificate(encodedCertificate);
        certificateFileWriter.close();
    }

}
