package de.rub.nds.x509attacker.x509.model.meta;

import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.TbsCertificate;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1Sequence;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class X509Certificate implements Referenceable {

    @XmlAttribute
    private int id = 0;

    @XmlAttribute
    private String keyFile = null;

    @XmlAttribute
    private String generateKeyForAlgorithm = null;

    @XmlAttribute
    private String outputFile = null;

    @XmlAttribute
    private boolean attachToCertificateList = true;

    @XmlElement
    private TbsCertificate tbsCertificate = null;

    @XmlElement
    private Signature signature = null;

    @XmlElement
    private RealSignatureInfo realSignatureInfo = null;

    @XmlTransient
    private X509Certificate issuer = null;

    @XmlTransient
    private int keyFileId = 0;

    public X509Certificate() {

    }

    public String getGenerateKeyForAlgorithm() {
        return generateKeyForAlgorithm;
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

    public void setGenerateKeyForAlgorithm(String generateKeyForAlgorithm) {
        this.generateKeyForAlgorithm = generateKeyForAlgorithm;
    }

    public X509Certificate getIssuer() {
        return issuer;
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

    public void setIssuer(X509Certificate issuer) {
        this.issuer = issuer;
    }

    public int getKeyFileId() {
        return keyFileId;
    }

    public void setKeyFileId(int keyFileId) {
        this.keyFileId = keyFileId;
    }

    public byte[] assembleCertificate() {
        X509CertificateSequence certificateSequence = new X509CertificateSequence();
        certificateSequence.addField(this.tbsCertificate);
        if (this.signature != null) {
            certificateSequence.addField(this.signature.getAlgorithmIdentifier());
            certificateSequence.addField(this.signature.getSignature());
        }
        return certificateSequence.encode();
    }

    protected class X509CertificateSequence extends X509Asn1Sequence {

    }
}
