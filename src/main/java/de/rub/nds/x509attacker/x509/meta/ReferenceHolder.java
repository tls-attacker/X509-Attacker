package de.rub.nds.x509attacker.x509.meta;

public interface ReferenceHolder {
    String getFromId();

    void setReferencedObject(Referenceable object) throws LinkingException;

    void updateReferencedFields();
}
