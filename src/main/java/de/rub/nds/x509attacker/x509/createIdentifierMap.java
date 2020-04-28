/*
 * Copyright 2019 josh.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1tool.xmlparser.AnonymousIdentifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 *
 * @author josh
 */
public class createIdentifierMap {
    
    
   
    
    private Map<String, Asn1Encodable> identifierMap;

    public createIdentifierMap() {
        identifierMap = new HashMap<>();
        
    }
    
    public Map<String, Asn1Encodable> createMap(final List<Asn1Encodable> asn1Encodables)
    { 
        
        this.crawlAsn1EncodedContentRecursive("", asn1Encodables);
        
        return identifierMap;
    }
    
   

    private void crawlAsn1EncodedContentRecursive(final String basePath, final List<Asn1Encodable> asn1Encodables) {
        if (asn1Encodables != null) {
            for (Asn1Encodable asn1Encodable : asn1Encodables) {
                
                if (asn1Encodable.getIdentifier() == null || asn1Encodable.getIdentifier().isEmpty()) {
                    asn1Encodable.setIdentifier(AnonymousIdentifier.createAnonymousIdentifier());
                }

                String fullPathIdentifier = basePath + "/" + asn1Encodable.getIdentifier();
                
                if (this.identifierMap.containsKey(fullPathIdentifier) == false) {
                    this.identifierMap.put(fullPathIdentifier, asn1Encodable);
                } else {
                    throw new RuntimeException("Identifier " + fullPathIdentifier + " is used more than once!");
                }
                
                if (asn1Encodable instanceof Asn1Container) {
                    this.crawlAsn1EncodedContentRecursive(
                            fullPathIdentifier,
                            ((Asn1Container) asn1Encodable).getChildren()
                    );
                }
            }
        }
    }

    
}
