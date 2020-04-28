
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveBitStringFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**

 * KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }
 * 
 */
public class KeyUsage extends X509Model<Asn1PrimitiveBitString> {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    
    public static final String OID = "2.5.29.15"; 
    private static final String type = "KeyUsage";
    
    
    
    public static KeyUsage getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new KeyUsage(intermediateAsn1Field, identifier);        
    }
    
    private KeyUsage(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        //keyIdentifier 
        asn1 = (Asn1PrimitiveBitString) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1PrimitiveBitStringFT.class , identifier, type);       
    } 
    
}
