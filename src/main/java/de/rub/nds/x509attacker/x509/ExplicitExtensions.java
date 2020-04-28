
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ExplicitFT;

/**

 *  extensions      [3]  EXPLICIT Extensions OPTIONAL
 * 
 */
public class ExplicitExtensions extends X509Model<Asn1Explicit> {
            
    private static final String type = "";    
    
    public Extensions extensions;        
    
    public static ExplicitExtensions getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new ExplicitExtensions(intermediateAsn1Field, identifier);        
    }
    
    private ExplicitExtensions(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        asn1 = (Asn1Explicit) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1ExplicitFT.class , identifier, "ExplicitContainer");
        
        if(intermediateAsn1Field.getChildren().size() == 1)
        {
            extensions = Extensions.getInstance(intermediateAsn1Field.getChildren().get(0), "extensions");           
        }
        asn1.addChild(extensions.asn1);   
        
    }  
     
    
}
