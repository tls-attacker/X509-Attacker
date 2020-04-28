
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;


public class X509Model<T extends Asn1Encodable>{    
    
    public T asn1;
    
    public T getAsn1()
    {
        return asn1;
    }
}
