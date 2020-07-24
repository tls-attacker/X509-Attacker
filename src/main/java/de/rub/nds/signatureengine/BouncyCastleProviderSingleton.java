
package de.rub.nds.signatureengine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author josh
 */
public class BouncyCastleProviderSingleton {

    private static BouncyCastleProvider instance;
    
    private BouncyCastleProviderSingleton(){}
    
    //static block initialization for exception handling
    static{
        try{
            instance = new BouncyCastleProvider();
        }catch(Exception e){
            throw new RuntimeException("Exception occured in creating singleton instance");
        }
    }
    
    public static BouncyCastleProvider getInstance(){
        return instance;
    }
}
