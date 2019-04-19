package de.rub.nds.x509.linker;

public interface Linkeable {

    /**
     * @return Returns the user-assigned identifier of the given object.
     */
    String getId();

    /**
     * Sets the user-assigned identifier to the given value.
     *
     * @param id The new identifier value.
     */
    void setId(String id);

    /**
     * @return Returns the identifier which specifies from which object properties shall be inherited.
     */
    String getFromId();

    /**
     * Sets the identifier which specifies from which object properties shall be inherited.
     *
     * @param fromId
     */
    void setFromId(String fromId);

    /**
     * Method is called by the field linker to pass the object that is referenced by fromId.
     *
     * @param object The object that is referenced by fromId.
     */
    void updateWithReferencedObject(Object object);
}
