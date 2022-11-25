package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.base.RelativeDistinguishedName;
import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The Subject of a Certificate becomes the issuer of the next certificate
 */
public class SubjectNameHandler extends X509Handler {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    private RelativeDistinguishedName rdnSequence;
    
    public SubjectNameHandler(RelativeDistinguishedName rdnSequence, X509Chooser chooser) {
        super(chooser);
        this.rdnSequence = rdnSequence;
    }
    
    @Override
    public void adjustContext() {
        LOGGER.debug("Reparsing RDN to update context");
        RelativeDistinguishedName parsedRdnSequence = new RelativeDistinguishedName("parsedRdn");
        parsedRdnSequence.getParser().parse(new ByteArrayInputStream(rdnSequence.getContent().getValue()));
        List<Pair<X500AttributeType, String>> rdnList = new LinkedList<>();
        for (Asn1Encodable encodable : parsedRdnSequence.getChildren()) {
            if (encodable instanceof AttributeTypeAndValue) {
                rdnList.add(new ImmutablePair<>(((AttributeTypeAndValue) encodable).getAttributeTypeConfig(), ((AttributeTypeAndValue) encodable).getValueConfig()));
            }
        }
        chooser.getContext().setIssuer(rdnList);
    }
}
