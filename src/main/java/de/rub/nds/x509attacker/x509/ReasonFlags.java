
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveBitStringFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**

 * ReasonFlags ::= BIT STRING {
        unused                  (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
        privilegeWithdrawn      (7),
        aACompromise            (8) }
 * 
 */
public class ReasonFlags extends X509Model<Asn1PrimitiveBitString> {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    
    private static final String type = "ReasonFlags";
    
    
    
    public static ReasonFlags getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new ReasonFlags(intermediateAsn1Field, identifier);        
    }
    
    private ReasonFlags(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        //ReasonFlags 
        asn1 = (Asn1PrimitiveBitString) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1PrimitiveBitStringFT.class , identifier, type);       
    } 
    
}
