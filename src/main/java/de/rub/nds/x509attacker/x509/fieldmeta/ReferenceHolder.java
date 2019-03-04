package de.rub.nds.x509attacker.x509.fieldmeta;

public interface ReferenceHolder {
    int getFromId();

    void setReferencedObject(Referenceable object) throws LinkingException;

    void updateReferencedFields();
}
