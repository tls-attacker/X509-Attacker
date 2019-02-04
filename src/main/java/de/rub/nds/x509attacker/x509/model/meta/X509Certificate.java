package de.rub.nds.x509attacker.x509.model.meta;

import de.rub.nds.x509attacker.x509.model.types.basiccertificate.TbsCertificate;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class X509Certificate {

    @XmlAttribute
    private int id;

    @XmlAttribute
    private String keyFile;

    @XmlAttribute
    private String outputFile;

    @XmlAttribute
    private boolean attachToCertificateList;

    @XmlElement
    private TbsCertificate tbsCertificate;

    @XmlElement
    private Signature signature;

    @XmlElement
    private RealSignatureInfo realSignatureInfo;

    public X509Certificate() {
        super();
        this.id = 0;
        this.keyFile = null;
        this.outputFile = null;
        this.attachToCertificateList = true;
        this.tbsCertificate = null;
        this.signature = null;
        this.realSignatureInfo = null;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
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

    public TbsCertificate getTbsCertificate() {
        return tbsCertificate;
    }

    public void setTbsCertificate(TbsCertificate tbsCertificate) {
        this.tbsCertificate = tbsCertificate;
    }

    public boolean hasTbsCertificate() {
        return this.tbsCertificate != null;
    }

    public RealSignatureInfo getRealSignatureInfo() {
        return realSignatureInfo;
    }

    public void setRealSignatureInfo(RealSignatureInfo realSignatureInfo) {
        this.realSignatureInfo = realSignatureInfo;
    }

    public boolean hasRealSignatureInfo() {
        return this.realSignatureInfo != null;
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }

    public boolean hasSignature() {
        return this.signature != null;
    }
}
