/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1BmpString;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1T61String;
import de.rub.nds.asn1.model.Asn1UniversalString;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.DirectoryString;

public class DirectoryStringPreparator implements X509Preparator {

    private final X509Chooser chooser;
    private final DirectoryString directoryString;

    public DirectoryStringPreparator(X509Chooser chooser, DirectoryString directoryString) {
        this.chooser = chooser;
        this.directoryString = directoryString;
    }

    @Override
    public void prepare() {
        switch (directoryString.getDirectoryStringChoiceType()) {
            case BMP_STRING:
                directoryString.makeSelection(directoryString.getBmpString());
                directoryString.setConfigValue(
                        directoryString.getBmpString().getValue().getValue());
                break;
            case PRINTABLE_STRING:
                directoryString.makeSelection(directoryString.getPrintableString());
                directoryString.setConfigValue(
                        directoryString.getPrintableString().getValue().getValue());
                break;
            case TELETEX_STRING:
                directoryString.makeSelection(directoryString.getTeletexString());
                directoryString.setConfigValue(
                        directoryString.getTeletexString().getValue().getValue());
                break;
            case UNIVERSAL_STRING:
                directoryString.makeSelection(directoryString.getUniversalString());
                directoryString.setConfigValue(
                        directoryString.getUniversalString().getValue().getValue());
                break;
            case UTF8_STRING:
                directoryString.makeSelection(directoryString.getUtf8String());
                directoryString.setConfigValue(
                        directoryString.getUtf8String().getValue().getValue());
                break;
            default:
                throw new UnsupportedOperationException(
                        "Unimplemented DirectoryStringChoiceType: "
                                + directoryString.getDirectoryStringChoiceType());
        }
        HelperPreparator<Asn1Field> helper =
                new HelperPreparator<>(
                        chooser,
                        (Asn1Field) directoryString.getSelectedChoice(),
                        directoryString.getConfigValue());
        helper.prepare();
        // TODO we are not adjusting the context here.
    }

    /** Small hack to get access to helper function */
    private class HelperPreparator<T extends Asn1Field> extends X509Asn1FieldPreparator<T> {

        private String value;

        public HelperPreparator(X509Chooser chooser, T type, String value) {
            super(chooser, type);
            this.value = value;
        }

        @Override
        protected byte[] encodeContent() {
            if (field instanceof Asn1BmpString) {
                Asn1PreparatorHelper.prepareField(((Asn1BmpString) field), value);
            } else if (field instanceof Asn1PrintableString) {
                Asn1PreparatorHelper.prepareField(((Asn1PrintableString) field), value);
            } else if (field instanceof Asn1T61String) {
                Asn1PreparatorHelper.prepareField(((Asn1T61String) field), value);
            } else if (field instanceof Asn1UniversalString) {
                Asn1PreparatorHelper.prepareField(((Asn1UniversalString) field), value);
            } else if (field instanceof Asn1Utf8String) {
                Asn1PreparatorHelper.prepareField(((Asn1Utf8String) field), value);
            } else {
                throw new UnsupportedOperationException(
                        "Unimplemented Asn1Field: " + field.getClass().getName());
            }
            return field.getContent().getOriginalValue();
        }
    }
}
