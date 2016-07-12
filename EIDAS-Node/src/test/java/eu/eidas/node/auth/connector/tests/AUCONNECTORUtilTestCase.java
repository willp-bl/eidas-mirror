/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations 
 * under the License.
 */
package eu.eidas.node.auth.connector.tests;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.Properties;

import com.hazelcast.core.Hazelcast;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.node.auth.ConcurrentMapService;
import eu.eidas.node.auth.ConcurrentMapServiceDefaultImpl;
import eu.eidas.node.auth.ConcurrentMapServiceDistributedImpl;
import eu.eidas.node.auth.connector.AUCONNECTORUtil;
import eu.eidas.node.auth.connector.ICONNECTORSAMLService;
import eu.eidas.node.auth.util.tests.TestingConstants;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Functional testing class to {@link AUCONNECTORUtil}.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUCONNECTORUtilTestCase {

    private static final Logger LOG = LoggerFactory.getLogger(AUCONNECTORUtilTestCase.class.getName());

    /**
     * Properties values for testing proposes.
     */
    private static Properties CONFIGS = new Properties();

    /**
     * Dummy PersonalAttributeList testing proposes.
     */
    private static IPersonalAttributeList ATTR_LIST = new PersonalAttributeList();

    /**
     * Properties values for EIDASUtil testing proposes.
     */
    private static Properties EIDASUTILS_CONFIGS = new Properties();

    private static final String ANTIREPLAY_SAML_ID_A = "SAML_ID_A";

    /**
     * Initialising class variables.
     *
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void runBeforeClass() throws Exception {
        ATTR_LIST.populate("Idade:false:[15,]:Available;");
    }

    @After
    public void after() throws Exception {

        Hazelcast.shutdownAll();
    }

  /**
   * Initialize the CONFIGS properties for each test to avoid
   * inherited configurations
   */
    @Before
    public void initialize(){
      CONFIGS = new Properties();
      CONFIGS.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),
              TestingConstants.ONE_CONS.toString());
    }
    /**
     * Test method for {@link AUCONNECTORUtil#loadConfig(String)} . Must Succeed.
     */
    @Test
    public void testLoadConfig() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setConfigs(CONFIGS);
        assertEquals(TestingConstants.ONE_CONS.toString(),
                auconnectorutil.loadConfig(EIDASParameters.EIDAS_NUMBER.toString()));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#loadConfig(String)} . Must return null.
     */
    @Test
    public void testLoadConfigMissing() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setConfigs(CONFIGS);
        assertNull(auconnectorutil.loadConfig(EIDASParameters.EIDAS_ASK_CONSENT_VALUE
                .toString()));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#loadConfigServiceURL(String)} . Must Return
     * null.
     */
    @Test
    public void testLoadConfigNodeURLMissing() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setConfigs(CONFIGS);
        CONFIGS.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        CONFIGS.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        CONFIGS.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());

        assertNull(auconnectorutil.loadConfigServiceURL(TestingConstants.LOCAL_CONS
                .toString()));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#loadConfigServiceURL(String)} . Must an
     * URL.
     */
    @Test
    public void testLoadConfigNodeURL() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setConfigs(CONFIGS);
        CONFIGS.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        CONFIGS.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        CONFIGS.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        CONFIGS.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());

        assertEquals(TestingConstants.LOCAL_URL_CONS.toString(),
                auconnectorutil.loadConfigServiceURL(TestingConstants.LOCAL_CONS.toString()));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#validateSP(Map)} .
     * Must return false.
     */
    @Test
    public void testValidateSPMissing() {

        final Map<String, String> parameters = mock(Map.class);
        when(parameters.get(EIDASParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.MAX_QAA_CONS.toString());
        when(parameters.get(EIDASParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auconnectorutil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());

        auconnectorutil.setConfigs(CONFIGS);

        assertFalse(auconnectorutil.validateSP(parameters));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#validateSP(Map)} .
     * Must return true.
     */
    @Test
    public void testValidateSP() {

        final Map<String, String> parameters = mock(Map.class);
        when(parameters.get(EIDASParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.QAALEVEL_CONS.toString());
        when(parameters.get(EIDASParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auconnectorutil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());
        CONFIGS.put(TestingConstants.SPID_CONS.getQaaLevel(),
                TestingConstants.QAALEVEL_CONS.toString());
        auconnectorutil.setConfigs(CONFIGS);

        assertTrue(auconnectorutil.validateSP(parameters));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#validateSPCertAlias(String, String)} .
     * Must return false.
     */
    @Test
    public void testValidateSPCertAliasMissing() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                + EIDASValues.VALIDATION_SUFFIX.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        auconnectorutil.setConfigs(CONFIGS);

        assertFalse(auconnectorutil.validateSPCertAlias(
                TestingConstants.PROVIDERNAME_CONS.toString(),
                TestingConstants.EMPTY_CONS.toString()));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#validateSPCertAlias(String, String)} .
     * Must return true.
     */
    @Test
    public void testValidateSPCertAliasAllowAll() {

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                + EIDASValues.VALIDATION_SUFFIX.toString(), EIDASValues.NONE.toString());
        auconnectorutil.setConfigs(CONFIGS);

        assertTrue(auconnectorutil.validateSPCertAlias(
                TestingConstants.PROVIDERNAME_CONS.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString()));
    }

    /**
     * Test method for {@link AUCONNECTORUtil#validateSPCertAlias(String, String)} .
     * Must return true.
     */
    @Test
    public void testValidateSPCertAlias() {

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                + EIDASValues.VALIDATION_SUFFIX.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        auconnectorutil.setConfigs(CONFIGS);

        assertTrue(auconnectorutil.validateSPCertAlias(
                TestingConstants.PROVIDERNAME_CONS.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString()));
    }

    /**
     * Test method for
     * {@link AUCONNECTORUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return false.
     */
    @Test
    public void testCheckContentsNoPermission() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.remove(TestingConstants.SPID_CONS.toString());
        auconnectorutil.setConfigs(CONFIGS);
        assertFalse(auconnectorutil.checkContents(
                TestingConstants.SPID_CONS.toString(), ATTR_LIST));
    }

    /**
     * Test method for
     * {@link AUCONNECTORUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return true.
     */
    @Test
    public void testCheckContentsAll() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(EIDASValues.DEFAULT.toString(),
                TestingConstants.ALL_CONS.toString());
        auconnectorutil.setConfigs(CONFIGS);
        assertTrue(auconnectorutil.checkContents(TestingConstants.SPID_CONS.toString(),
                ATTR_LIST));
    }

    /**
     * Test method for
     * {@link AUCONNECTORUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return false.
     */
    @Test
    public void testCheckContentsNotAllowed() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.SPID_CONS.toString(),
                TestingConstants.EMPTY_CONS.toString());

        auconnectorutil.setConfigs(CONFIGS);
        assertFalse(auconnectorutil.checkContents(
                TestingConstants.SPID_CONS.toString(), ATTR_LIST));
    }

    /**
     * Test method for
     * {@link AUCONNECTORUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return true.
     */
    @Test
    public void testCheckContents() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.SPID_CONS.toString(),
                TestingConstants.ALLOWED_ATTRIBUTES_CONS.toString());

        auconnectorutil.setConfigs(CONFIGS);
        assertTrue(auconnectorutil.checkContents(TestingConstants.SPID_CONS.toString(),
                ATTR_LIST));
    }

    /**
     * Checks the default antireplay Cache.
     */
    @Test
    public void testDefaultAntiReplayMechanism() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setAntiReplayCache(auconnectorutil.getConcurrentMapService().getNewAntiReplayCache());
        auconnectorutil.flushReplayCache();
        // This is the first case a SAML id is submitted in the cache
        assertTrue("FIRST pass of replay attack", auconnectorutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
        // Second submission of same value, replay attack must be detected
        assertFalse("Second pass of replay attack", auconnectorutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
    }
    /**
     * Checks the default anti-replay Cache.
     */
    @Test
    public void testHazelcastAntiReplayMechanism() {
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        ConcurrentMapServiceDistributedImpl hazelCache = new ConcurrentMapServiceDistributedImpl();
        hazelCache.setAntiReplayCacheName("myTestCache");
        auconnectorutil.setConcurrentMapService(hazelCache);
        auconnectorutil.setAntiReplayCache(auconnectorutil.getConcurrentMapService().getNewAntiReplayCache());
        auconnectorutil.flushReplayCache();
        // This is the first case a SAML id is submitted in the cache
        assertTrue("FIRST pass of replay attack", auconnectorutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
        // Second submission of same value, replay attack must be detected
        assertFalse("Second pass of replay attack", auconnectorutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
    }
    @Test(expected=InvalidParameterEIDASException.class)
    public void testHazelCastAntiReplayMechanismFailByNullCache(){
        ConcurrentMapServiceDistributedImpl hazelCache = new ConcurrentMapServiceDistributedImpl();
        hazelCache.getNewAntiReplayCache();
    }
    @Test(expected=IllegalArgumentException.class)
    public void testHazelCastAntiReplayMechanismFail() throws Exception{
        LOG.info("************************************************************************");
        ConcurrentMapServiceDistributedImpl hazelCache = new ConcurrentMapServiceDistributedImpl();
        hazelCache.setAntiReplayCacheName("myTestCache");
        hazelCache.setHazelcastXmlConfigClassPathFileName("TEST");
        hazelCache.getNewAntiReplayCache();
    }
}