
package de.rub.nds.x509attacker.identifiermap;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1tool.xmlparser.AnonymousIdentifier;
import de.rub.nds.x509attacker.exceptions.X509ModificationException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
* Main class for the mapping of identifiers and the corresponding Asn1Elements
* Contains a Hashmap Key:= Path of Identifiers (ex.: /root/inter/leaf)
* Value:= the corresponding Asn1Element behind the path
* 
* Is dynamically created of a given Asn1Structure (List<Asn1Encodable>) and provides an API for accessing specific 
* ASN1 elements of a structure.
*/
public class IdentifierMap {
    
    private static final Logger LOGGER = LogManager.getLogger(IdentifierMap.class);
    
    private Map<String, Asn1Encodable> map;    
    
    
    /**
    * Creates the Hashmap of the given Asn1Structure (List<Asn1Encodable>) 
    * 
    * @param asn1Encodables The List<Asn1Encodable> for which the IdentifierMap is created
    */    
    public IdentifierMap(final List<Asn1Encodable> asn1Encodables) {
        map = new HashMap<>();
        createMap(asn1Encodables);
    }
    
    public IdentifierMap(final Map<String, Asn1Encodable> map) {
        this.map = map;
    }
    
    public Map<String, Asn1Encodable> getMap() {
        return map;
    }

    public void setMap(Map<String, Asn1Encodable> map) {
        this.map = map;
    }
    
    
    /**
     * Returns the ASN1 element of a given path of identifiers.
     *
     * @param idPath The path of identifiers to an ASN1 element of the X509certificate.
     * @return the Asn1Encodable object of the given path or null if path is not available
     * 
     */
    public Asn1Encodable getElementByIDPath(String idPath){
        
        if(idPath.length() > 1 && idPath.charAt(0) != '/')
        {
            idPath = '/'+idPath;
        }
        
        if(idPath.length() > 1 && idPath.charAt(idPath.length()-1) == '/')
        {
            idPath = idPath.substring(0,idPath.length()-1);
        }
        
        Asn1Encodable asn1Element = map.get(idPath);
        
        if(asn1Element == null)
        {
            LOGGER.trace("getElementByIDPath(): no mapping for : " + idPath);
        }
                
        return asn1Element;
    }
    
    /**
     * Returns all ASN1 elements with a given identifier.
     *
     * @param id The identifier of an element, which is searched for.
     * @return a List of Asn1Encodable objects for the given identifier 
     */
    public List<Asn1Encodable> getElementsByID(String id){
        
        if(id.equals(""))
        {
            return null;
        }
        
        List<Asn1Encodable> asn1List = map.entrySet().stream()
                .filter(x->x.getValue().getIdentifier().equals(id))
                .map(x->x.getValue())
                .collect(Collectors.toList());
        
        
        if(asn1List.isEmpty())
        {
            LOGGER.trace("getElementsByID(): no mapping for : " + id);
            return null;
        }
                
        return asn1List;
    }
    
    
    /**
     * Returns all ASN1 elements with a given type.
     *
     *@param type The type ASN1 element to search.
     *@return a List of Asn1Encodable objects for the given identifier 
     */    
    public List<Asn1Encodable> getElementsByType(String type)
    {
        if(type.equals(""))
        {
            return null;
        }
        
        List<Asn1Encodable> asn1List = map.entrySet().stream()
                .filter(x->x.getValue().getType().equals(type))
                .map(x->x.getValue())
                .collect(Collectors.toList());
        
        
        if(asn1List.isEmpty())
        {
            LOGGER.trace("getElementsByType(): no mapping for : " + type);
            return null;
        }
                
        return asn1List;
    }
    
    
    
    /**
     * Returns all Asn1Elements which has the same 
     * class or are an instance of the given class
     *
     *@param asn1Class The asn1Class to search, must implement Asn1Encodable
     *@return a List of Asn1Encodable objects for the given identifier 
     */    
    public List<Asn1Encodable> getElementsByClass(Class asn1Class)
    {
        if(asn1Class == null || !Asn1Encodable.class.isAssignableFrom(asn1Class))
        {
            return null;
        }
        
        List<Asn1Encodable> asn1List = map.entrySet().stream()
                .filter(x-> asn1Class.isAssignableFrom(x.getValue().getClass()))  
                .map(x->x.getValue())
                .collect(Collectors.toList());
        
        
        if(asn1List.isEmpty())
        {
            LOGGER.trace("getElementsByClass(): no mapping for : " + asn1Class);
            return null;
        }
                
        return asn1List;
    }
    
    
    
    /**
     * Returns the identifier Path of a given ASN1 element.
     *
     * @param asn1 The asn1Element which Path is searched
     * @return The Path of identifiern to the given ASN.1 elemen
     * 
     */
    public String getIDPathByElement(Asn1Encodable asn1){
        
        if(asn1 == null ) {
            return "";
        }
        
        if(!map.containsValue(asn1)) {
            LOGGER.trace("getIDPathByElement(): no mapping for : " + asn1);
            return "";
        }
           
        Optional<String> idPath = map.entrySet().stream().
                filter(x->x.getValue() == asn1)
                .map(x->x.getKey())
                .findFirst();
        
       return idPath.orElse("");
    }
    
    /**
     * Returns all identifier Paths to a given Identifier
     *
     * @param id The identifier of an element, which is searched for.
     * @return a List of identifier paths for the given identifier 
     */
    public List<String> getIDPathsByID(String id){
        
        if(id.equals(""))
        {
            return null;
        }
        
        List<String> idPaths = map.entrySet().stream()
                .filter(x->x.getValue().getIdentifier().equals(id))
                .map(x->x.getKey())
                .collect(Collectors.toList());
        
        
        if(idPaths.isEmpty())
        {
            LOGGER.trace("getIDPathsByID(): no mapping for : " + id);
            return null;
        }
                
        return idPaths;
    }
    
    
    /**
     * Returns all identifier Paths to a given type.
     *
     *@param type The type ASN1 element to search.
     *@return a List of identifier paths for the given identifier 
     */    
    public List<String> getIDPathsByType(String type)
    {
        if(type.equals(""))
        {
            return null;
        }
        
        List<String> idPaths = map.entrySet().stream()
                .filter(x->x.getValue().getType().equals(type))
                .map(x->x.getKey())
                .collect(Collectors.toList());
        
        
        if(idPaths.isEmpty())
        {
            LOGGER.trace("getIDPathsByType(): no mapping for : " + type);
            return null;
        }
                
        return idPaths;
    }
    
    
    /**
     * Returns all identifier Paths of Asn1Encodable object which has the same 
     * class or are an instance of the given class
     *
     *@param asn1Class The asn1Class to search, must implement Asn1Encodable
     *@return a List of identifier paths for the given identifier 
     */    
    public List<String> getIDPathsByClass(Class asn1Class)
    {        
        if(asn1Class == null || !Asn1Encodable.class.isAssignableFrom(asn1Class))
        {
            return null;
        }
        
        List<String> idPaths = map.entrySet().stream()
                .filter(x-> asn1Class.isAssignableFrom(x.getValue().getClass()))                
                .map(x->x.getKey())
                .collect(Collectors.toList());
        
        
        if(idPaths.isEmpty())
        {
            LOGGER.trace("getIDPathsByClass(): no mapping for : " + asn1Class.getSimpleName());
            return null;
        }
                
        return idPaths;
    }
    
    
    /**
     * Returns a deep copy of the ASN1 element of a given path of identifiers.
     *
     * @param path The path of identifiers to an ASN1 element of the X509certificate.
     * @return the Asn1Encodable object as a deep copy of the given path or null if path is not available
     * 
     */
    public Asn1Encodable getCopyByIDPath(String path){
        
        Asn1Encodable asn1 = getElementByIDPath(path);
        Asn1Encodable asn1Copy = null;
        if(asn1 != null)
        {
            try
            {
                //asn1Copy = Asn1EncodableSerializer.copyAsn1Encodable(asn1);
                asn1Copy = asn1.getCopy();
            }
            catch(XMLStreamException | JAXBException | IOException e)
            {
                LOGGER.trace("getCopyByIDPath(): Copy failed : " + e);
            }
            
        }
                
        return asn1Copy;
    }
    
      
    /**
     * Sets the given Asn1Encdoable in the ASN1 structure of the X509Certificate at the position, described in the given path.
     * It overwrites Asn1Encodable object under the given path.
     * 
     * 
     * @param path The path where to set the Asn1Encodable.
     * @param asn1Encodable The Asn1Encodable Object to setElementByIDPath at the given path
     * @throws X509ModificationException if an Exception occurs while modifying the Asn1 strucutre of the X509Certificat
     * 
     */
    public void setElementByIDPath(String path, Asn1Encodable asn1Encodable) throws X509ModificationException
    {
        if(asn1Encodable == null)
        {
             throw new X509ModificationException("setElementByIDPath(): asn1Encodable is null");
        }
        
        
        if(path.endsWith("/"))
        {
            path = path.substring(0,path.length()-1);
        }
        
        //Extract parentPath and identifier
        String parentPath = path.substring(0, path.lastIndexOf("/"));
        String identifier = path.substring(path.lastIndexOf("/")+1, path.length());
        
        
        //get Parent Asn1Object
        Asn1Encodable asn1Parent = this.getElementByIDPath(parentPath);
        
        if(asn1Parent == null)
        {
            throw new X509ModificationException("setElementByIDPath(): There is no parent Object " + parentPath);
        }
        
        if(asn1Parent instanceof Asn1Container)
        {
            //in the parentObject the new Asn1Encodable has to be set as one of the children
            List<Asn1Encodable> childrens = ((Asn1Container) asn1Parent).getChildren();
                        
            //check if identifier is already available as children of parent (return index of child)           
            int index = IntStream.range(0, childrens.size()).filter(childIndex -> childrens.get(childIndex).getIdentifier().equals(identifier)).findFirst().orElse(-1);
            
            if(index != -1)
            {                
                //overwrites child
                childrens.set(index, asn1Encodable);
            }
            else
            {
                //add new child
                 childrens.add(asn1Encodable);
            }
            
            //set correct identifier of the new inserted Asn1Encodable Element
            asn1Encodable.setIdentifier(identifier);
            //set the modified children list back to the parent object
            ((Asn1Container) asn1Parent).setChildren(childrens);
        }
        else
        {
            throw new X509ModificationException("setElementByIDPath(): There parent Object is no instance of an Asn1Container " + parentPath);
        }
    }
    
    /**
     * Removes the Asn1Encodable at the given Identifier Path.
     * The Asn1Encodable must be a child of a Asn1Container.
     * 
     * @param path The path where to remove the Asn1Encodable.
     * @throws X509ModificationException if an Exception occurs while modifying the Asn1 strucutre of the X509Certificat
     * 
     */
    public void removeElementByIDPath(String path) throws X509ModificationException
    {
        
        if(path.endsWith("/"))
        {
            path = path.substring(0,path.length()-1);
        }
        
        if(map.containsKey(path) == false)
        {
             throw new X509ModificationException("removeElementByIDPath(): map does not contain an Asn1Encodable at" + path);
        }
        
        //Extract parentPath and identifier
        String parentPath = path.substring(0, path.lastIndexOf("/"));
        String identifier = path.substring(path.lastIndexOf("/")+1, path.length());
        
        
        //get Parent Asn1Object
        Asn1Encodable asn1Parent = this.getElementByIDPath(parentPath);
        
        if(asn1Parent == null)
        {
            throw new X509ModificationException("removeElementByIDPath(): There is no parent Object " + parentPath);
        }
        
        if(asn1Parent instanceof Asn1Container)
        {
            //in the parentObject the new Asn1Encodable has to be setElementByIDPath as one of the children
            List<Asn1Encodable> childrens = ((Asn1Container) asn1Parent).getChildren();
                        
            //get index of the identifier as a child of parent          
            int index = IntStream.range(0, childrens.size()).filter(childIndex -> childrens.get(childIndex).getIdentifier().equals(identifier)).findFirst().orElse(-1);
            
            childrens.remove(index);
            
            //set the modified children list back to the parent object
            ((Asn1Container) asn1Parent).setChildren(childrens);
        }
        else
        {
            throw new X509ModificationException("removeElementByIDPath(): There parent Object is no instance of an Asn1Container " + parentPath);
        }
    }
  
  
    /**
     * Creates the Hashmap by crawling through each ASN1 element of the given ASN1 strcuture (List<Asn1Encodable>)
     *
     * @param param asn1Encodables The List<Asn1Encodable> for which the IdentifierMap is created.
     * 
     */
    private void createMap(final List<Asn1Encodable> asn1Encodables)
    {         
        this.crawlAsn1EncodedContentRecursive("", asn1Encodables);
    }
    
   

    private void crawlAsn1EncodedContentRecursive(final String basePath, final List<Asn1Encodable> asn1Encodables) {
        if (asn1Encodables != null) {
            for (Asn1Encodable asn1Encodable : asn1Encodables) {
                if(asn1Encodable == null)
                {
                    continue;
                }
                
                if (asn1Encodable.getIdentifier() == null || asn1Encodable.getIdentifier().isEmpty()) {
                    asn1Encodable.setIdentifier(AnonymousIdentifier.createAnonymousIdentifier());
                }

                String fullPathIdentifier = basePath + "/" + asn1Encodable.getIdentifier();
                
                if (this.map.containsKey(fullPathIdentifier) == false) {
                    this.map.put(fullPathIdentifier, asn1Encodable);
                } else {
                    throw new RuntimeException("IdentifierMap -> crawlAsn1EncodedContentRecursive(): Identifier " + fullPathIdentifier + " is used more than once!");
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
