/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Ia5String;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.GeneralName;

public class GeneralNamePreparator implements X509Preparator {

    private final GeneralName generalName;
    private final X509Chooser chooser;

    public GeneralNamePreparator(X509Chooser chooser, GeneralName generalName) {
        this.generalName = generalName;
        this.chooser = chooser;
    }

    @Override
    public void prepare() {

        byte contextTag;

        switch (generalName.getGeneralNameChoiceTypeConfig()) {
            case DIRECTORY_NAME:
                generalName.makeSelection(generalName.getDirectoryName());
                contextTag = (byte) 0x84;
                break;
            case DNS_NAME:
                generalName.makeSelection(generalName.getDnsName());
                contextTag = (byte) 0x82;
                break;
            case EDI_PARTY_NAME:
                generalName.makeSelection(generalName.getEdiPartyName());
                contextTag = (byte) 0x85;
                break;
            case IP_ADDRESS:
                generalName.makeSelection(generalName.getIpAddress());
                contextTag = (byte) 0x87;
                break;
            case OTHER_NAME:
                generalName.makeSelection(generalName.getOtherName());
                contextTag = (byte) 0x80;
                break;
            case REGISTERED_ID:
                generalName.makeSelection(generalName.getRegisteredId());
                contextTag = (byte) 0x88;
                break;
            case RFC822_NAME:
                generalName.makeSelection(generalName.getRfc822Name());
                contextTag = (byte) 0x81;
                break;
            case UNIFORM_RESOURCE_IDENTIFIER:
                generalName.makeSelection(generalName.getUniformResourceIdentifier());
                contextTag = (byte) 0x86;
                break;
            case X400_ADDRESS:
                generalName.makeSelection(generalName.getX400Address());
                contextTag = (byte) 0x83;
                break;
            default:
                throw new UnsupportedOperationException(
                        "GeneralNameChoiceType "
                                + generalName.getGeneralNameChoiceTypeConfig().name()
                                + " not yet implemented.");
        }

        if (generalName.getSelectedChoice() instanceof Asn1Field) {
            HelperPreparator<Asn1Field> preparator =
                    new HelperPreparator<>(
                            chooser,
                            (Asn1Field) generalName.getSelectedChoice(),
                            generalName.getGeneralNameConfigValue(),
                            contextTag);
            preparator.prepareWithTag();
        } else {
            throw new UnsupportedOperationException(
                    "GeneralName only supports Asn1Field and X509 Components at the time");
        }
    }

    /** Small hack to get access to helper function */
    private class HelperPreparator<T extends Asn1Field> extends X509Asn1FieldPreparator<T> {

        private final Object value;
        private final byte contextTag;

        public HelperPreparator(X509Chooser chooser, T type, Object value, byte contextTag) {
            super(chooser, type);
            this.value = value;
            this.contextTag = contextTag;
        }

        @Override
        protected byte[] encodeContent() {
            switch (field) {
                case Asn1Ia5String asn1Ia5String ->
                        Asn1PreparatorHelper.prepareField(asn1Ia5String, (String) value);
                case Asn1ObjectIdentifier asn1ObjectIdentifier ->
                        Asn1PreparatorHelper.prepareField(
                                asn1ObjectIdentifier, new ObjectIdentifier((String) value));
                case Asn1OctetString asn1OctetString ->
                        Asn1PreparatorHelper.prepareField(asn1OctetString, (byte[]) value);
                default ->
                        throw new UnsupportedOperationException(
                                "Unimplemented Asn1Field: " + field.getClass().getName());
            }
            return field.getContent().getOriginalValue();
        }

        public void prepareWithTag() {
            super.prepare();

            // set context-specific tag
            this.field.setTagOctets(new byte[] {contextTag});

            // set outer length
            this.field.setLengthOctets(new byte[] {(byte) (field.getContent().getValue().length)});
        }
    }
}
