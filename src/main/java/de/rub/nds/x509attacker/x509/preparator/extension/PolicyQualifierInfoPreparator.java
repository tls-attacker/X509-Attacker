/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifierInfo;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class PolicyQualifierInfoPreparator extends X509ContainerPreparator<PolicyQualifierInfo> {
    public PolicyQualifierInfoPreparator(X509Chooser chooser, PolicyQualifierInfo container) {
        super(chooser, container);
    }

    @Override
    public void prepareSubComponents() {
        Asn1PreparatorHelper.prepareField(
                field.getPolicyQualifierId(), field.getPolicyObjectIdentifier());

        switch (field.getQualifierChoiceType()) {
            case CPSURI:
                if (field.getQualifierString() != null) {
                    Asn1Ia5String string = new Asn1Ia5String("qualifier");
                    string.setValue(field.getQualifierString());
                    field.setQualifier(string);

                    Asn1PreparatorHelper.prepareField(
                            (Asn1Ia5String) field.getQualifier(), field.getQualifierString());
                } else {
                    Asn1OctetString octetString = new Asn1OctetString("qualifier");
                    octetString.setValue(field.getQualifierOctetString());
                    field.setQualifier(octetString);

                    Asn1PreparatorHelper.prepareField(
                            (Asn1OctetString) field.getQualifier(),
                            field.getQualifierOctetString());
                }
                break;
            case USERNOTICE:
                List<Asn1Encodable> userNoticeChildren = new ArrayList<>();
                Asn1UnknownSequence wrappingSequenceUserNotice =
                        new Asn1UnknownSequence("userNotice");

                if (field.getIncludeNoticeRef()) {
                    List<Asn1Encodable> noticeRefChildren = new ArrayList<>();
                    Asn1UnknownSequence wrappingSequenceNoticeRef =
                            new Asn1UnknownSequence("noticeRef");

                    switch (field.getNoticeRefOrganizationType()) {
                        case IA5STRING:
                            Asn1Ia5String explicitTextIa5 = new Asn1Ia5String("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextIa5, field.getNoticeRefOrganization());
                            noticeRefChildren.add(explicitTextIa5);
                            break;
                        case VISIBLESTRING:
                            Asn1VisibleString explicitTextVisible =
                                    new Asn1VisibleString("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextVisible, field.getNoticeRefOrganization());
                            noticeRefChildren.add(explicitTextVisible);
                            break;
                        case BMPSTRING:
                            Asn1BmpString explicitTextBmp = new Asn1BmpString("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextBmp, field.getNoticeRefOrganization());
                            noticeRefChildren.add(explicitTextBmp);
                            break;
                        case UTF8STRING:
                            Asn1Utf8String explicitTextUtf8 = new Asn1Utf8String("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextUtf8, field.getNoticeRefOrganization());
                            noticeRefChildren.add(explicitTextUtf8);
                            break;
                    }

                    Asn1UnknownSequence wrappingSequenceNoticeNumbers =
                            new Asn1UnknownSequence("noticeNumbers");
                    List<Asn1Encodable> noticeNumberChildren = new ArrayList<>();
                    for (long noticeNumber : field.getNoticeRefNoticeNumbers()) {
                        Asn1Integer noticeNumberAsn1 =
                                new Asn1Integer("noticeNumber" + noticeNumber);
                        Asn1PreparatorHelper.prepareField(
                                noticeNumberAsn1, BigInteger.valueOf(noticeNumber));
                        noticeNumberChildren.add(noticeNumberAsn1);
                    }
                    wrappingSequenceNoticeNumbers.setContent(encodeChildren(noticeNumberChildren));
                    Asn1PreparatorHelper.prepareAfterContent(wrappingSequenceNoticeNumbers);
                    noticeRefChildren.add(wrappingSequenceNoticeNumbers);

                    wrappingSequenceNoticeRef.setContent(encodeChildren(noticeRefChildren));
                    Asn1PreparatorHelper.prepareAfterContent(wrappingSequenceNoticeRef);
                    userNoticeChildren.add(wrappingSequenceNoticeRef);
                }

                if (field.getIncludeExplicitText()) {
                    switch (field.getExplicitTextType()) {
                        case IA5STRING:
                            Asn1Ia5String explicitTextIa5 = new Asn1Ia5String("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextIa5, field.getExplicitText());
                            userNoticeChildren.add(explicitTextIa5);
                            break;
                        case VISIBLESTRING:
                            Asn1VisibleString explicitTextVisible =
                                    new Asn1VisibleString("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextVisible, field.getExplicitText());
                            userNoticeChildren.add(explicitTextVisible);
                            break;
                        case BMPSTRING:
                            Asn1BmpString explicitTextBmp = new Asn1BmpString("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextBmp, field.getExplicitText());
                            userNoticeChildren.add(explicitTextBmp);
                            break;
                        case UTF8STRING:
                            Asn1Utf8String explicitTextUtf8 = new Asn1Utf8String("explicitText");
                            Asn1PreparatorHelper.prepareField(
                                    explicitTextUtf8, field.getExplicitText());
                            userNoticeChildren.add(explicitTextUtf8);
                            break;
                    }
                }
                wrappingSequenceUserNotice.setContent(encodeChildren(userNoticeChildren));
                Asn1PreparatorHelper.prepareAfterContent(wrappingSequenceUserNotice);

                field.setQualifier(wrappingSequenceUserNotice);
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(field.getPolicyQualifierId(), field.getQualifier());
    }
}
