package de.rub.nds.asn1.parser;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class IntermediateAsn1Field {

    private int tagClass = 0;

    private boolean isConstructed = false;

    private int tagNumber = 0;

    private BigInteger length = BigInteger.ZERO;

    private byte[] content = new byte[0];

    private List<IntermediateAsn1Field> children = new LinkedList<>();

    public IntermediateAsn1Field() {

    }

    public int getTagClass() {
        return tagClass;
    }

    public void setTagClass(int tagClass) {
        this.tagClass = tagClass;
    }

    public boolean isConstructed() {
        return isConstructed;
    }

    public void setConstructed(boolean constructed) {
        isConstructed = constructed;
    }

    public int getTagNumber() {
        return tagNumber;
    }

    public void setTagNumber(int tagNumber) {
        this.tagNumber = tagNumber;
    }

    public BigInteger getLength() {
        return length;
    }

    public void setLength(BigInteger length) {
        this.length = length;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public List<IntermediateAsn1Field> getChildren() {
        return children;
    }

    public void setChildren(List<IntermediateAsn1Field> children) {
        this.children = children;
    }

    public void addChild(IntermediateAsn1Field intermediateAsn1Field) {
        this.children.add(intermediateAsn1Field);
    }

    public void addChildren(List<IntermediateAsn1Field> intermediateAsn1Fields) {
        if(intermediateAsn1Fields != null) {
            for(IntermediateAsn1Field intermediateAsn1Field : intermediateAsn1Fields) {
                this.addChild(intermediateAsn1Field);
            }
        }
    }

    public boolean containsChildren() {
        return !this.children.isEmpty();
    }
}
