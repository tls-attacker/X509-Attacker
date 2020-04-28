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
package de.rub.nds.x509attacker.helper;

import de.rub.nds.signatureengine.keyparsers.KeyType;
import java.io.File;
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
public class KeyFactoryTest {
    
    private File keyFolder;
    
    public KeyFactoryTest() {
    }
    
    @Before
    public void setUp() throws Exception {
        keyFolder = new File("resources/keys");
    }

    /**
     * Test of getRandomKeyFileFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomKeyFileFromFolder() throws Exception {
        File result = KeyFactory.getRandomKeyFileFromFolder(keyFolder, null);
        assertNotNull(result);
        assertTrue(result.getAbsolutePath().contains(keyFolder.getAbsolutePath()));
        
    }
    
    
    /**
     * Test of getRandomKeyFileFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomKeyFileFromFolder_File() throws Exception {
        File result = KeyFactory.getRandomKeyFileFromFolder(keyFolder, null);
        assertNotNull(result);
        assertTrue(result.getAbsolutePath().contains(keyFolder.getAbsolutePath()));
    }

    /**
     * Test of getRandomKeyFileFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomKeyFileFromFolder_File_KeyType() throws Exception {
        File result = KeyFactory.getRandomKeyFileFromFolder(keyFolder, KeyType.RSA);
        assertNotNull(result);
        assertTrue(result.getAbsolutePath().contains(keyFolder.getAbsolutePath()));
    }
    
}
