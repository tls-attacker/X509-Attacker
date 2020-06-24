/*
 * Copyright 2020 josh.
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
package de.rub.nds.signatureengine.keyparsers;

import java.io.File;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.crypto.tls.Certificate;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author josh
 */
public class PemUtilTest {
    
    public PemUtilTest() {
    }
   
    /**
     * Test of readPublicKey method, of class PemUtil.
     */
    //@Test
    public void testReadPrivateKey_File() throws Exception {
        System.out.println("readPublicKey");
        File f = new File("/home/josh/newKeys/rsa/rsa2048key.pem");
        PrivateKey result = PemUtil.readPrivateKey(f);
        
        int i = 3;
    }
    
    @Test
    public void testReadPublicKey_File() throws Exception {
        System.out.println("readPublicKey");
        File f = new File("/home/josh/newKeys/pkcs8Test/rsa/rsa_1024.pem");
        PrivateKey result = PemUtil.readKeyPEM(f);
        
        int i = 3;
    }

    
    
}
