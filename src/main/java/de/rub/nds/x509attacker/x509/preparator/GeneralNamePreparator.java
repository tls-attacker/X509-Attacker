/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.X509Component;

public class GeneralNamePreparator implements X509Preparator {

    private final GeneralName generalName;
    private final X509Chooser chooser;

    public GeneralNamePreparator(X509Chooser chooser, GeneralName generalName) {
        this.generalName = generalName;
        this.chooser = chooser;
    }

    @Override
    public void prepare() {
        switch (generalName.getGeneralNameChoiceTypeConfig()) {
            case DIRECTORY_NAME:
                generalName.makeSelection(generalName.getDirectoryName());
                break;
            case DNS_NAME:
                generalName.makeSelection(generalName.getDnsName());
                break;
            case EDI_PARTY_NAME:
                generalName.makeSelection(generalName.getEdiPartyName());
                break;
            case IP_ADDRESS:
                generalName.makeSelection(generalName.getIpAddress());
                break;
            case OTHER_NAME:
                generalName.makeSelection(generalName.getOtherName());
                break;
            case REGISTERED_ID:
                generalName.makeSelection(generalName.getRegisteredId());
                break;
            case RFC822_NAME:
                generalName.makeSelection(generalName.getRfc822Name());
                break;
            case UNIFORM_RESOURCE_IDENTIFIER:
                generalName.makeSelection(generalName.getUniformResourceIdentifier());
                break;
            case X400_ADDRESS:
                generalName.makeSelection(generalName.getX400Address());
                break;
            default:
                throw new UnsupportedOperationException(
                        "GeneralNameChoiceType "
                                + generalName.getGeneralNameChoiceTypeConfig().name()
                                + " not yet implemented.");
        }
        if (generalName instanceof X509Component) {
            ((X509Component) generalName).getPreparator(chooser).prepare();
        } else {
            HelperPreparator<Asn1Field> preparator =
                    new HelperPreparator<Asn1Field>(
                            chooser,
                            (Asn1Field)
                                    generalName.getSelectedChoice(), // TODO this is not safe....
                            generalName.getGeneralNameConfigValue());
            preparator.prepare();
        }
    }

    /** Small hack to get access to helper function */
    private class HelperPreparator<T extends Asn1Field> extends X509Asn1FieldPreparator<T> {

        private Object value;

        public HelperPreparator(X509Chooser chooser, T type, Object value) {
            super(chooser, type);
            this.value = value;
        }

        @Override
        protected byte[] encodeContent() {
            if (field instanceof Asn1Ia5String) {
                prepareField(((Asn1Ia5String) field), (String) value);
            } else if (field instanceof Asn1ObjectIdentifier) {
                prepareField(((Asn1ObjectIdentifier) field), new ObjectIdentifier((String) value));
            } else if (field instanceof Asn1OctetString) {
                prepareField(((Asn1OctetString) field), (byte[]) value);
            } else {
                throw new UnsupportedOperationException(
                        "Unimplemented Asn1Field: " + field.getClass().getName());
            }
            return field.getContent().getOriginalValue();
        }
    }
}
