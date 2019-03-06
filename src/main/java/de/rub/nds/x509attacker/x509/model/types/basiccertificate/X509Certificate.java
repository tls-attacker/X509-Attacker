package de.rub.nds.x509attacker.x509.model.types.basiccertificate;

import de.rub.nds.x509attacker.x509.model.nonasn1.RealSignatureInfo;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1Sequence;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class X509Certificate extends X509Asn1Sequence {

    @XmlAttribute
    private String keyFile = null;

    @XmlAttribute
    private String generateKeyForAlgorithm = null;

    @XmlAttribute
    private String outputFile = null;

    @XmlAttribute
    private boolean attachToCertificateList = true;

    @XmlElements(
            @XmlElement(name = "realSignatureInfo", type = RealSignatureInfo.class)
    )
    private List<RealSignatureInfo> realSignatureInfos = new LinkedList<>();

    @XmlTransient
    private X509Certificate issuer = null;

    @XmlTransient
    private int keyFileId = 0;

    @XmlTransient
    private byte[] toBeSigned = null;

    @XmlTransient
    private byte[] generatedCertificate = null;

    public X509Certificate() {

    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public String getGenerateKeyForAlgorithm() {
        return generateKeyForAlgorithm;
    }

    public void setGenerateKeyForAlgorithm(String generateKeyForAlgorithm) {
        this.generateKeyForAlgorithm = generateKeyForAlgorithm;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    public boolean isAttachToCertificateList() {
        return attachToCertificateList;
    }

    public void setAttachToCertificateList(boolean attachToCertificateList) {
        this.attachToCertificateList = attachToCertificateList;
    }

    public List<RealSignatureInfo> getRealSignatureInfos() {
        return realSignatureInfos;
    }

    public void setRealSignatureInfos(List<RealSignatureInfo> realSignatureInfos) {
        this.realSignatureInfos = realSignatureInfos;
    }

    public X509Certificate getIssuer() {
        return issuer;
    }

    public void setIssuer(X509Certificate issuer) {
        this.issuer = issuer;
    }

    public int getKeyFileId() {
        return keyFileId;
    }

    public void setKeyFileId(int keyFileId) {
        this.keyFileId = keyFileId;
    }

    public byte[] getToBeSigned() {
        return toBeSigned;
    }

    public void setToBeSigned(byte[] toBeSigned) {
        this.toBeSigned = toBeSigned;
    }

    public byte[] getGeneratedCertificate() {
        return generatedCertificate;
    }

    public void setGeneratedCertificate(byte[] generatedCertificate) {
        this.generatedCertificate = generatedCertificate;
    }
}
