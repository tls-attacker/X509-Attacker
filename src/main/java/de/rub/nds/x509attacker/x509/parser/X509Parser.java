package de.rub.nds.x509attacker.x509.parser;

import java.io.InputStream;

public interface X509Parser {
    public abstract void parse(InputStream inputStream);
}
