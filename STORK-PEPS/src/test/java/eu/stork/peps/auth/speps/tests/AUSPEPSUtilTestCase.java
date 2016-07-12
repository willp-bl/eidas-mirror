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
package eu.stork.peps.auth.speps.tests;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.Properties;

import com.hazelcast.core.Hazelcast;
import eu.stork.peps.auth.ConcurrentMapService;
import eu.stork.peps.auth.ConcurrentMapServiceDefaultImpl;
import eu.stork.peps.auth.ConcurrentMapServiceDistributedImpl;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import eu.stork.peps.auth.engine.core.SAMLExtensionFormat;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.speps.AUSPEPSUtil;
import eu.stork.peps.auth.speps.ISPEPSSAMLService;
import eu.stork.peps.auth.util.tests.TestingConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Functional testing class to {@link AUSPEPSUtil}.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUSPEPSUtilTestCase {

    private static final Logger LOG = LoggerFactory.getLogger(AUSPEPSUtilTestCase.class.getName());

    /**
     * Properties values for testing proposes.
     */
    private static Properties CONFIGS = new Properties();

    /**
     * Dummy PersonalAttributeList testing proposes.
     */
    private static IPersonalAttributeList ATTR_LIST = new PersonalAttributeList();

    /**
     * Properties values for PEPSUtil testing proposes.
     */
    private static Properties PEPSUTILS_CONFIGS = new Properties();

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
      CONFIGS.setProperty(PEPSParameters.PEPS_NUMBER.toString(),
              TestingConstants.ONE_CONS.toString());
    }
    /**
     * Test method for {@link AUSPEPSUtil#loadConfig(String)} . Must Succeed.
     */
    @Test
    public void testLoadConfig() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsutil.setConfigs(CONFIGS);
        assertEquals(TestingConstants.ONE_CONS.toString(),
                auspepsutil.loadConfig(PEPSParameters.PEPS_NUMBER.toString()));
    }

    /**
     * Test method for {@link AUSPEPSUtil#loadConfig(String)} . Must return null.
     */
    @Test
    public void testLoadConfigMissing() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsutil.setConfigs(CONFIGS);
        assertNull(auspepsutil.loadConfig(PEPSParameters.PEPS_ASK_CONSENT_VALUE
                .toString()));
    }

    /**
     * Test method for {@link AUSPEPSUtil#loadConfigPepsURL(String)} . Must Return
     * null.
     */
    @Test
    public void testLoadConfigPepsURLMissing() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsutil.setConfigs(CONFIGS);
        CONFIGS.setProperty(PEPSParameters.PEPS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        CONFIGS.setProperty(PEPSValues.CPEPS_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        CONFIGS.setProperty(PEPSValues.CPEPS_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());

        assertNull(auspepsutil.loadConfigPepsURL(TestingConstants.LOCAL_CONS
                .toString()));
    }

    /**
     * Test method for {@link AUSPEPSUtil#loadConfigPepsURL(String)} . Must an
     * URL.
     */
    @Test
    public void testLoadConfigPepsURL() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsutil.setConfigs(CONFIGS);
        CONFIGS.setProperty(PEPSParameters.PEPS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        CONFIGS.setProperty(PEPSValues.CPEPS_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        CONFIGS.setProperty(PEPSValues.CPEPS_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        CONFIGS.setProperty(PEPSValues.CPEPS_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());

        assertEquals(TestingConstants.LOCAL_URL_CONS.toString(),
                auspepsutil.loadConfigPepsURL(TestingConstants.LOCAL_CONS.toString()));
    }

    /**
     * Test method for {@link AUSPEPSUtil#validateSP(Map)} .
     * Must return false.
     */
    @Test
    public void testValidateSPMissing() {
        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);

        final Map<String, String> parameters = mock(Map.class);
        when(parameters.get(PEPSParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.MAX_QAA_CONS.toString());
        when(parameters.get(PEPSParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsutil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auspepsutil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());

        auspepsutil.setConfigs(CONFIGS);

        assertFalse(auspepsutil.validateSP(parameters));
    }

    /**
     * Test method for {@link AUSPEPSUtil#validateSP(Map)} .
     * Must return true.
     */
    @Test
    public void testValidateSP() {
        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);

        final Map<String, String> parameters = mock(Map.class);
        when(parameters.get(PEPSParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.QAALEVEL_CONS.toString());
        when(parameters.get(PEPSParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsutil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auspepsutil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());
        CONFIGS.put(TestingConstants.SPID_CONS.getQaaLevel(),
                TestingConstants.QAALEVEL_CONS.toString());
        auspepsutil.setConfigs(CONFIGS);

        assertTrue(auspepsutil.validateSP(parameters));
    }

    /**
     * Test method for {@link AUSPEPSUtil#validateSPCertAlias(String, String)} .
     * Must return false.
     */
    @Test
    public void testValidateSPCertAliasMissing() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                + PEPSValues.VALIDATION_SUFFIX.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        auspepsutil.setConfigs(CONFIGS);

        assertFalse(auspepsutil.validateSPCertAlias(
                TestingConstants.PROVIDERNAME_CONS.toString(),
                TestingConstants.EMPTY_CONS.toString()));
    }

    /**
     * Test method for {@link AUSPEPSUtil#validateSPCertAlias(String, String)} .
     * Must return true.
     */
    @Test
    public void testValidateSPCertAliasAllowAll() {
        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                + PEPSValues.VALIDATION_SUFFIX.toString(), PEPSValues.NONE.toString());
        auspepsutil.setConfigs(CONFIGS);

        assertTrue(auspepsutil.validateSPCertAlias(
                TestingConstants.PROVIDERNAME_CONS.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString()));
    }

    /**
     * Test method for {@link AUSPEPSUtil#validateSPCertAlias(String, String)} .
     * Must return true.
     */
    @Test
    public void testValidateSPCertAlias() {
        final ISPEPSSAMLService spepsSAMLService = mock(ISPEPSSAMLService.class);

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                + PEPSValues.VALIDATION_SUFFIX.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        auspepsutil.setConfigs(CONFIGS);

        assertTrue(auspepsutil.validateSPCertAlias(
                TestingConstants.PROVIDERNAME_CONS.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString()));
    }

    /**
     * Test method for
     * {@link AUSPEPSUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return false.
     */
    @Test
    public void testCheckContentsNoPermission() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.remove(TestingConstants.SPID_CONS.toString());
        auspepsutil.setConfigs(CONFIGS);
        assertFalse(auspepsutil.checkContents(
                TestingConstants.SPID_CONS.toString(), ATTR_LIST));
    }

    /**
     * Test method for
     * {@link AUSPEPSUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return true.
     */
    @Test
    public void testCheckContentsAll() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(PEPSValues.DEFAULT.toString(),
                TestingConstants.ALL_CONS.toString());
        auspepsutil.setConfigs(CONFIGS);
        assertTrue(auspepsutil.checkContents(TestingConstants.SPID_CONS.toString(),
                ATTR_LIST));
    }

    /**
     * Test method for
     * {@link AUSPEPSUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return false.
     */
    @Test
    public void testCheckContentsNotAllowed() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.SPID_CONS.toString(),
                TestingConstants.EMPTY_CONS.toString());

        auspepsutil.setConfigs(CONFIGS);
        assertFalse(auspepsutil.checkContents(
                TestingConstants.SPID_CONS.toString(), ATTR_LIST));
    }

    /**
     * Test method for
     * {@link AUSPEPSUtil#checkContents(String, IPersonalAttributeList)} . Must
     * return true.
     */
    @Test
    public void testCheckContents() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        CONFIGS.put(TestingConstants.SPID_CONS.toString(),
                TestingConstants.ALLOWED_ATTRIBUTES_CONS.toString());

        auspepsutil.setConfigs(CONFIGS);
        assertTrue(auspepsutil.checkContents(TestingConstants.SPID_CONS.toString(),
                ATTR_LIST));
    }

    /**
     * Checks the default antireplay Cache.
     */
    @Test
    public void testDefaultAntiReplayMechanism() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsutil.setAntiReplayCache(auspepsutil.getConcurrentMapService().getNewAntiReplayCache());
        auspepsutil.flushReplayCache();
        // This is the first case a SAML id is submitted in the cache
        assertTrue("FIRST pass of replay attack", auspepsutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
        // Second submission of same value, replay attack must be detected
        assertFalse("Second pass of replay attack", auspepsutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
    }
    /**
     * Checks the default anti-replay Cache.
     */
    @Test
    public void testHazelcastAntiReplayMechanism() {
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        ConcurrentMapServiceDistributedImpl hazelCache = new ConcurrentMapServiceDistributedImpl();
        hazelCache.setAntiReplayCacheName("myTestCache");
        auspepsutil.setConcurrentMapService(hazelCache);
        auspepsutil.setAntiReplayCache(auspepsutil.getConcurrentMapService().getNewAntiReplayCache());
        auspepsutil.flushReplayCache();
        // This is the first case a SAML id is submitted in the cache
        assertTrue("FIRST pass of replay attack", auspepsutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
        // Second submission of same value, replay attack must be detected
        assertFalse("Second pass of replay attack", auspepsutil.checkNotPresentInCache(ANTIREPLAY_SAML_ID_A, "EU"));
    }
    @Test(expected=InvalidParameterPEPSException.class)
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