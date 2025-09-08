/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;
import de.rub.nds.x509attacker.x509.model.extensions.AuthorityKeyIdentifier;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.ArrayUtils;

public class AuthorityKeyIdentifierPreparator
        extends ExtensionPreparator<AuthorityKeyIdentifier, AuthorityKeyIdentifierConfig> {
    public AuthorityKeyIdentifierPreparator(
            X509Chooser chooser,
            AuthorityKeyIdentifier container,
            AuthorityKeyIdentifierConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        // TODO: Probably refactor into Asn1 classes that hold context-specific tags

        if (config.getKeyIdentifier() != null) {
            Asn1PreparatorHelper.prepareField(field.getKeyIdentifier(), config.getKeyIdentifier());

            // prepend original tag and length to content
            field.getKeyIdentifier()
                    .setContent(
                            ArrayUtils.addAll(
                                    field.getKeyIdentifier().getLengthOctets().getValue(),
                                    field.getKeyIdentifier().getContent().getValue()));
            field.getKeyIdentifier()
                    .setContent(
                            ArrayUtils.addAll(
                                    field.getKeyIdentifier().getTagOctets().getValue(),
                                    field.getKeyIdentifier().getContent().getValue()));

            // set context-specific tag
            field.getKeyIdentifier().setTagOctets(new byte[] {(byte) 0xa0});

            // set outer length
            field.getKeyIdentifier()
                    .setLengthOctets(
                            new byte[] {
                                (byte) (field.getKeyIdentifier().getContent().getValue().length)
                            });
        }

        if (config.getGeneralNameConfigValue() != null
                && config.getGeneralNameChoiceTypeConfig() != null) {
            field.getAuthorityCertIssuer()
                    .setGeneralNames(List.of(config.getAuthorityCertIssuer()));
            field.getAuthorityCertIssuer().getPreparator(chooser).prepare();

            // prepend original tag and length to content
            field.getAuthorityCertIssuer()
                    .setContent(
                            ArrayUtils.addAll(
                                    field.getAuthorityCertIssuer().getLengthOctets().getValue(),
                                    field.getAuthorityCertIssuer().getContent().getValue()));
            field.getAuthorityCertIssuer()
                    .setContent(
                            ArrayUtils.addAll(
                                    field.getAuthorityCertIssuer().getTagOctets().getValue(),
                                    field.getAuthorityCertIssuer().getContent().getValue()));

            // set context-specific tag
            field.getAuthorityCertIssuer().setTagOctets(new byte[] {(byte) 0xa1});

            // set outer length
            field.getAuthorityCertIssuer()
                    .setLengthOctets(
                            new byte[] {
                                (byte)
                                        (field.getAuthorityCertIssuer()
                                                .getContent()
                                                .getValue()
                                                .length)
                            });
        }

        if (config.getSerialNumber() != 0) {
            Asn1PreparatorHelper.prepareField(
                    field.getAuthorityCertSerialNumber(),
                    BigInteger.valueOf(config.getSerialNumber()));

            // prepend original tag and length to content
            field.getAuthorityCertSerialNumber()
                    .setContent(
                            ArrayUtils.addAll(
                                    field.getAuthorityCertSerialNumber()
                                            .getLengthOctets()
                                            .getValue(),
                                    field.getAuthorityCertSerialNumber().getContent().getValue()));
            field.getAuthorityCertSerialNumber()
                    .setContent(
                            ArrayUtils.addAll(
                                    field.getAuthorityCertSerialNumber().getTagOctets().getValue(),
                                    field.getAuthorityCertSerialNumber().getContent().getValue()));

            // set context-specific tag
            field.getAuthorityCertSerialNumber().setTagOctets(new byte[] {(byte) 0xa2});

            // set outer length
            field.getAuthorityCertSerialNumber()
                    .setLengthOctets(
                            new byte[] {
                                (byte)
                                        (field.getAuthorityCertSerialNumber()
                                                .getContent()
                                                .getValue()
                                                .length)
                            });
        }

        field.getWrappingSequence().setContent(encodeSequenceContent());
        Asn1PreparatorHelper.prepareAfterContent(field.getWrappingSequence());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getWrappingSequence());
    }

    private byte[] encodeSequenceContent() {
        List<Asn1Encodable> children = new ArrayList<>();

        if (config.getKeyIdentifier() != null) {
            children.add(field.getKeyIdentifier());
        }

        if (config.getGeneralNameConfigValue() != null
                && config.getGeneralNameChoiceTypeConfig() != null) {
            children.add(field.getAuthorityCertIssuer());
        }

        if (config.getSerialNumber() != 0) {
            children.add(field.getAuthorityCertSerialNumber());
        }

        return encodeChildren(children);
    }
}
