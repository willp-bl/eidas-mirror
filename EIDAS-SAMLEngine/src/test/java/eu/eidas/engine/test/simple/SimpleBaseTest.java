/* 
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 * 
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */

package eu.eidas.engine.test.simple;

import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.X500PrincipalUtil;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;

import junit.framework.Assert;
import junit.framework.TestCase;
import static org.junit.Assert.fail;

/**
 * The Class SimpleBaseTest. Defines a set of test the initialization of the
 * SAML engine.
 */
public class SimpleBaseTest extends TestCase {

    /**
     * Test SAML engine correct configuration name.
     */
    @Test
    public final void testSamlEngineCorrectInit() {
        try {
            Assert.assertNotNull(EIDASSAMLEngine.createSAMLEngine("CONF1"));
        }catch(EIDASSAMLEngineException e){
            fail("Failed to initialize SAMLEngines");
        }
    }

    /**
     * Test SAML engine error configuration name.
     */
    @Test
    public final void testSamlEngineErrorNameConf() {
        try {
            Assert.assertNull(EIDASSAMLEngine.createSAMLEngine("CONF_ERROR"));
            fail("expected SAMLEngine cannot be loaded");
        }catch(EIDASSAMLEngineException e){
            //expected samlengine in error
        }
    }

    /**
     * Test SAML engine error name null.
     */
    @Test
    public final void testSamlEngineErrorNameNull() {
        try {
            Assert.assertNull(EIDASSAMLEngine.createSAMLEngine(null));
        }catch(EIDASSAMLEngineException e){
            fail("Failed to initialize SAMLEngines");
        }
    }

    /**
     * Test SAML engine correct name configuration with spaces.
     */
    @Test
    public final void testSamlEngineErrorNameSpaces() {
        try {
            Assert.assertNotNull(EIDASSAMLEngine.createSAMLEngine("   CONF1    "));
        }catch(EIDASSAMLEngineException e){
            fail("Failed to initialize SAMLEngines");
        }
    }

    @Test
    public final void testSamlEngineUtils() throws EIDASSAMLEngineException{
        Assert.assertNotNull(SAMLEngineUtils.encode("TEST", SAMLEngineUtils.SHA_512));
        Assert.assertNotNull(SAMLEngineUtils.generateKeyInfo());
        Assert.assertNotNull(SAMLEngineUtils.generateNameID());

    }
    @Test
    public final void testX509PrincipalsUtils() {
        System.out.println("*********************************************");
        X500Name test1 = new X500Name("C=AU,ST=Victoria");
        X500Name test2 = new X500Name("CN=Thawte Timestamping CA, OU=Thawte Certification, O=Thawte, L=Durbanville, ST=Western Cape, C=ZA");
        Assert.assertTrue(X500PrincipalUtil.principalEquals(test2, test2));
        Assert.assertFalse(X500PrincipalUtil.principalEquals(null, null));
        Assert.assertFalse(X500PrincipalUtil.principalEquals(test2, null));
        Assert.assertFalse(X500PrincipalUtil.principalEquals(null, test2));
        Assert.assertFalse(X500PrincipalUtil.principalEquals(test1, test2));
    }

}
