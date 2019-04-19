package de.rub.nds.x509attacker.filesystem;

import de.rub.nds.x509.model.X509CertificateList;
import de.rub.nds.x509.model.rfc5280.X509Certificate;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;

public class CertificateFileWriter {

    private static final String CERT_PREFIX = "-----BEGIN CERTIFICATE-----\n";

    private static final String CERT_SUFFIX = "\n-----END CERTIFICATE-----\n";

    private final String certificateDirectory;

    private static int certCounter = 1;

    public CertificateFileWriter(final String certificateDirectory) {
        this.certificateDirectory = certificateDirectory;
    }

    public void writeCertificates(final X509CertificateList x509CertificateList) throws IOException {
        StringBuilder allCertificatesStringBuilder = new StringBuilder();
        for(X509Certificate x509Certificate : x509CertificateList.getCertificates()) {
            String certificateName = this.computeCertificateName(x509Certificate);
            String certificateString = this.computeCertificateString(x509Certificate);
            this.writeCertificateContent(certificateName, certificateString);
            allCertificatesStringBuilder.append(certificateString);
        }
        this.writeCertificateContent("all_certificates.pem", allCertificatesStringBuilder.toString());
    }

    private String computeCertificateName(final X509Certificate x509Certificate) {
        String certificateName = x509Certificate.getId();
        if(certificateName == null || certificateName.isEmpty()) {
            certificateName = "_cert" + (certCounter++);
        }
        return certificateName + ".pem";
    }

    private String computeCertificateString(final X509Certificate x509Certificate) {
        byte[] signedCertificate = x509Certificate.getSignedCertificateBytes();
        StringBuilder certificateStringBuilder = new StringBuilder();
        certificateStringBuilder.append(CERT_PREFIX);
        certificateStringBuilder.append(Base64.toBase64String(signedCertificate));
        certificateStringBuilder.append(CERT_SUFFIX);
        return certificateStringBuilder.toString();
    }

    private void writeCertificateContent(final String filename, final String content) throws IOException {
        BinaryFileWriter binaryFileWriter = new BinaryFileWriter(this.certificateDirectory, filename);
        binaryFileWriter.write(content.getBytes());
    }
}
