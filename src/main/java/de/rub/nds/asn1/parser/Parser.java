package de.rub.nds.asn1.parser;

import java.util.List;

public abstract class Parser {

    private final byte[] bytes;

    private int readPosition = 0;

    public Parser(final byte[] bytes) {
        this.bytes = bytes;
    }

    public byte peekByte() throws ParserException {
        byte result = 0;
        if(readPosition < this.bytes.length) {
            result = this.bytes[readPosition];
        }
        else {
            throw new ParserException("Cannot peekByte: Next byte not available!");
        }
        return result;
    }

    public byte[] peekBytes(int length) throws ParserException {
        byte[] result = null;
        if((readPosition + length) < this.bytes.length) {
            result = new byte[length];
            System.arraycopy(this.bytes, this.readPosition, result, 0, length);
        }
        else {
            throw new ParserException("Cannot peekByte: Next " + length + " bytes not available!");
        }
        return result;
    }

    public byte readByte() throws ParserException {
        byte result = this.peekByte();
        this.readPosition++;
        return result;
    }

    public byte[] readBytes(int length) throws ParserException{
        byte[] result = this.peekBytes(length);
        this.readPosition += length;
        return result;
    }

    public int getNumberOfRemainingBytes() {
        int numRemainingBytes = 0;
        if(this.readPosition < this.bytes.length) {
            numRemainingBytes = this.bytes.length - this.readPosition;
        }
        return numRemainingBytes;
    }

    public byte[] getRemainingBytes() throws ParserException {
        byte[] result = null;
        int numRemainingBytes = this.getNumberOfRemainingBytes();
        if(numRemainingBytes > 0) {
            result = this.peekBytes(numRemainingBytes);
        }
        else {
            throw new ParserException("Cannot read remaining bytes since no bytes are left!");
        }
        return result;
    }

    public int getNumberOfReadBytes() {
        return this.readPosition;
    }

    public abstract List<IntermediateAsn1Field> parse() throws ParserException;
}
