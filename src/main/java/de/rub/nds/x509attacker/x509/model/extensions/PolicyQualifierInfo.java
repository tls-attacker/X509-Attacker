/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.DisplayText;
import de.rub.nds.x509attacker.constants.PolicyQualifierChoiceType;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.PolicyQualifierInfoPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId, qualifier ANY DEFINED BY
 * policyQualifierId } }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PolicyQualifierInfo extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private Asn1ObjectIdentifier policyQualifierId;
    private ObjectIdentifier policyObjectIdentifier;

    @HoldsModifiableVariable
    @XmlAnyElement(lax = true)
    private Asn1Encodable qualifier;

    // Qualifier choosing
    private PolicyQualifierChoiceType qualifierChoiceType;

    // CPSuri
    // can prepare both string and octet string will, prefer string if non-null
    private String qualifierString;
    private byte[] qualifierOctetString;

    // UserNotice
    private Boolean includeNoticeRef;
    private String noticeRefOrganization;
    private DisplayText noticeRefOrganizationType;
    private List<Long> noticeRefNoticeNumbers;
    private Boolean includeExplicitText;
    private String explicitText;
    private DisplayText explicitTextType;

    private PolicyQualifierInfo() {
        super(null);
    }

    public PolicyQualifierInfo(String identifier) {
        super(identifier);
        policyQualifierId = new Asn1ObjectIdentifier("policyQualifiersId");
        qualifierChoiceType = PolicyQualifierChoiceType.CPSURI;
    }

    public Asn1ObjectIdentifier getPolicyQualifierId() {
        return policyQualifierId;
    }

    public void setPolicyQualifierId(Asn1ObjectIdentifier policyQualifierId) {
        this.policyQualifierId = policyQualifierId;
    }

    public Asn1Encodable getQualifier() {
        return qualifier;
    }

    public void setQualifier(Asn1Encodable qualifier) {
        this.qualifier = qualifier;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new PolicyQualifierInfoPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public ObjectIdentifier getPolicyObjectIdentifier() {
        return policyObjectIdentifier;
    }

    public void setPolicyObjectIdentifier(ObjectIdentifier policyObjectIdentifier) {
        this.policyObjectIdentifier = policyObjectIdentifier;
    }

    public String getQualifierString() {
        return qualifierString;
    }

    public void setQualifierString(String qualifierString) {
        this.qualifierString = qualifierString;
    }

    public byte[] getQualifierOctetString() {
        return qualifierOctetString;
    }

    public void setQualifierOctetString(byte[] qualifierOctetString) {
        this.qualifierOctetString = qualifierOctetString;
    }

    public PolicyQualifierChoiceType getQualifierChoiceType() {
        return qualifierChoiceType;
    }

    public void setQualifierChoiceType(PolicyQualifierChoiceType qualifierChoiceType) {
        this.qualifierChoiceType = qualifierChoiceType;
    }

    public Boolean getIncludeNoticeRef() {
        return includeNoticeRef;
    }

    public void setIncludeNoticeRef(Boolean includeNoticeRef) {
        this.includeNoticeRef = includeNoticeRef;
    }

    public String getNoticeRefOrganization() {
        return noticeRefOrganization;
    }

    public void setNoticeRefOrganization(String noticeRefOrganization) {
        this.noticeRefOrganization = noticeRefOrganization;
    }

    public List<Long> getNoticeRefNoticeNumbers() {
        return noticeRefNoticeNumbers;
    }

    public void setNoticeRefNoticeNumbers(List<Long> noticeRefNoticeNumbers) {
        this.noticeRefNoticeNumbers = noticeRefNoticeNumbers;
    }

    public Boolean getIncludeExplicitText() {
        return includeExplicitText;
    }

    public void setIncludeExplicitText(Boolean includeExplicitText) {
        this.includeExplicitText = includeExplicitText;
    }

    public String getExplicitText() {
        return explicitText;
    }

    public void setExplicitText(String explicitText) {
        this.explicitText = explicitText;
    }

    public DisplayText getNoticeRefOrganizationType() {
        return noticeRefOrganizationType;
    }

    public void setNoticeRefOrganizationType(DisplayText noticeRefOrganizationType) {
        this.noticeRefOrganizationType = noticeRefOrganizationType;
    }

    public DisplayText getExplicitTextType() {
        return explicitTextType;
    }

    public void setExplicitTextType(DisplayText explicitTextType) {
        this.explicitTextType = explicitTextType;
    }
}
