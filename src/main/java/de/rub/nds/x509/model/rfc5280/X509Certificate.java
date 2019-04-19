package de.rub.nds.x509.model.rfc5280;

import de.rub.nds.x509.model.RealSignatureInfo;
import de.rub.nds.x509.model.X509FieldContainer;
import de.rub.nds.x509.model.asn1.X509Asn1Sequence;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Certificate extends X509Asn1Sequence {

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
    private byte[] toBeSignedBytes = null;

    @XmlTransient
    private byte[] signedCertificateBytes = null;

    public X509Certificate() {
        super();
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

    public byte[] getToBeSignedBytes() {
        return toBeSignedBytes;
    }

    public void setToBeSignedBytes(byte[] toBeSignedBytes) {
        this.toBeSignedBytes = toBeSignedBytes;
    }

    public byte[] getSignedCertificateBytes() {
        return signedCertificateBytes;
    }

    public void setSignedCertificateBytes(byte[] signedCertificateBytes) {
        this.signedCertificateBytes = signedCertificateBytes;
    }
}
