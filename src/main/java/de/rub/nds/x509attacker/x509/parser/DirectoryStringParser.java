package de.rub.nds.x509attacker.x509.parser;

import java.io.InputStream;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.DirectoryString;

public class DirectoryStringParser implements X509Parser {

    public DirectoryStringParser(X509Chooser chooser, DirectoryString directoryString) {
    }

    @Override
    public void parse(InputStream inputStream) {
        throw new UnsupportedOperationException("Unimplemented method 'parse'");
    }

}
