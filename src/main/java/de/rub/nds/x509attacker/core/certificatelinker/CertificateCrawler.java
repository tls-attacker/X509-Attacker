package de.rub.nds.x509attacker.core.certificatelinker;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.x509.fieldmeta.X509Asn1FieldHolder;
import de.rub.nds.x509attacker.x509.fieldmeta.X509Asn1ValueHolder;

import java.util.LinkedList;
import java.util.List;

public abstract class CertificateCrawler {

    public CertificateCrawler() {

    }

    public abstract void handleField(Asn1RawField rawField) throws CertificateLinkerException;

    public void crawl(Asn1RawField rawField) throws CertificateLinkerException {
        final LinkedList<Asn1RawField> fieldList = new LinkedList<>();
        Asn1RawField field = null;
        fieldList.add(rawField);
        while (fieldList.isEmpty() == false) {
            if (fieldList.peek() instanceof Asn1RawField == false) {
                throw new CertificateLinkerException("The given certificate structure contains an element unknown to X.509-Attacker!");
            }
            field = fieldList.poll();
            this.handleField(field);
            this.addChildrenToFieldList(fieldList, field);
        }
    }

    private void addChildrenToFieldList(final List<Asn1RawField> fieldList, final Asn1RawField field) {
        List<Asn1RawField> children = null;
        if (field instanceof X509Asn1FieldHolder) {
            children = ((X509Asn1FieldHolder) field).getFields();
        }
        if (field instanceof X509Asn1ValueHolder) {
            children = ((X509Asn1ValueHolder) field).getValues();
        }
        if (children != null) {
            fieldList.addAll(children);
        }
    }
}
