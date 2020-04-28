
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import java.util.LinkedList;
import java.util.List;

/**

 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 * 
 * 
 */
public class Extensions extends X509Model<Asn1Sequence> {
    
 
    private static final String type = "Extensions";
    
    public List<Extension> extension;    
    
    
    public static Extensions getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier){
        
        return new Extensions(intermediateAsn1Field, identifier);        
    }
    
    private Extensions(IntermediateAsn1Field intermediateAsn1Field, String identifier)
    {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SequenceFT.class , identifier, type);
        
        extension = new LinkedList<>();
        int index = 0;
        for(IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            extension.add(Extension.getInstance(interFieldChild, "extension"+index++));
            asn1.addChild(extension.get(extension.size()-1).asn1);
        }   
        
    }  
     
    
}
