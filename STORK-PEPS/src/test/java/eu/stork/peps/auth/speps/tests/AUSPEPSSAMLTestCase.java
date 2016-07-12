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
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.peps.init.StorkSAMLEngineFactory;
import eu.stork.peps.auth.ConcurrentMapServiceDefaultImpl;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml2.core.StatusCode;
import org.springframework.context.MessageSource;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.IStorkLogger;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.exceptions.InternalErrorPEPSException;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import eu.stork.peps.auth.commons.exceptions.InvalidSessionPEPSException;
import eu.stork.peps.auth.commons.exceptions.SecurityPEPSException;
import eu.stork.peps.auth.speps.AUSPEPSSAML;
import eu.stork.peps.auth.speps.AUSPEPSUtil;
import eu.stork.peps.auth.speps.ISPEPSSAMLService;
import eu.stork.peps.auth.util.tests.TestingConstants;

/**
 * Functional testing class to {@link eu.stork.peps.auth.speps.AUSPEPSCountrySelector}.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUSPEPSSAMLTestCase {
    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUSPEPSSAMLTestCase.class.getName());


    /**
     * Dummy Personal Attribute List for testing proposes.
     */
    private static IPersonalAttributeList ATTR_LIST = new PersonalAttributeList();

    /**
     * Properties values for testing proposes.
     */
    private static Properties CONFIGS = new Properties();

    /**
     * SAML token array for testing proposes.
     */
    private static byte[] SAML_TOKEN_ARRAY = new byte[]{60, 115, 97, 109, 108, 62, 46, 46,
            46, 60, 47, 115, 97, 109, 108, 62};

    /**
     * Initialising class variables.
     *
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void runBeforeClass() throws Exception {

        ATTR_LIST.populate("eIdentifier:true:[]:Available;");

        CONFIGS.setProperty(PEPSValues.HASH_DIGEST_CLASS.toString(),
                "org.bouncycastle.crypto.digests.SHA512Digest");
        CONFIGS.setProperty(PEPSParameters.VALIDATION_ACTIVE.toString(),
                TestingConstants.TRUE_CONS.toString());

        CONFIGS.setProperty("max.SAMLRequest.size", "131072");
        CONFIGS.setProperty("max.SAMLResponse.size", "131072");
        CONFIGS.setProperty("max.spUrl.size", "150");
        CONFIGS.setProperty("max.attrList.size", "20000");
        CONFIGS.setProperty("max.providerName.size", "128");
        CONFIGS.setProperty("max.spQaaLevel.size", "1");
        CONFIGS.setProperty("max.spId.size", "40");
        CONFIGS.setProperty("max.cpepsRedirectUrl.size", "300");

        PEPSUtil.createInstance(CONFIGS);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateErrorAuthenticationResponse(String, String, String, String, String, String, String)}
     * . Testing with no instance set. Must throw and {@link NullPointerException}
     * .
     */
    @Test(expected = NullPointerException.class)
    public void testGenerateErrorAuthenticationResponseInvalidSamlInstance() {
        final ISPEPSSAMLService auspepssaml = new AUSPEPSSAML();
        ((AUSPEPSSAML)auspepssaml).setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.generateErrorAuthenticationResponse(
                TestingConstants.SAML_ID_CONS.toString(),
                TestingConstants.ISSUER_CONS.toString(),
                TestingConstants.DESTINATION_CONS.name(),
                TestingConstants.USER_IP_CONS.toString(),
                TestingConstants.ERROR_CODE_CONS.toString(),
                TestingConstants.SUB_ERROR_CODE_CONS.toString(),
                TestingConstants.ERROR_MESSAGE_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateErrorAuthenticationResponse(String, String, String, String, String, String, String)}
     * . Testing with no Saml id that will led to a saml engine exception. Must
     * throw and {@link NullPointerException}.
     */
    @Test(expected = InternalErrorPEPSException.class)
    public void testGenerateErrorAuthenticationResponseInvalidSamlData() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.generateErrorAuthenticationResponse(
                TestingConstants.EMPTY_CONS.toString(),
                TestingConstants.ISSUER_CONS.toString(),
                TestingConstants.DESTINATION_CONS.name(),
                TestingConstants.USER_IP_CONS.toString(),
                TestingConstants.ERROR_CODE_CONS.toString(),
                TestingConstants.SUB_ERROR_CODE_CONS.toString(),
                TestingConstants.ERROR_MESSAGE_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateErrorAuthenticationResponse(String, String, String, String, String, String, String)}
     * . Must succeed.
     */
    @Test
    public void testGenerateErrorAuthenticationResponse() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        byte[] token = auspepssaml.generateErrorAuthenticationResponse(
                TestingConstants.SAML_ID_CONS.toString(),
                TestingConstants.ISSUER_CONS.toString(),
                TestingConstants.DESTINATION_CONS.name(),
                TestingConstants.USER_IP_CONS.toString(),
                TestingConstants.ERROR_CODE_CONS.toString(),
                TestingConstants.SUB_ERROR_CODE_CONS.toString(),
                TestingConstants.ERROR_MESSAGE_CONS.toString());
        assertNotNull(token);
    }

    /**
     * Test method for {@link AUSPEPSSAML#getSAMLToken(Map, String, boolean)} .
     * Testing with a null saml token. Must throw an
     * {@link InvalidParameterPEPSException}.
     */
    @Test(expected = InvalidParameterPEPSException.class)
    public void testGetSAMLTokenNull() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final Map<String, String> parameters = new HashMap<String, String>();
        auspepssaml.getSAMLToken(parameters,
                PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), true);
    }

    /**
     * Test method for {@link AUSPEPSSAML#getSAMLToken(Map, String, boolean)} .
     * Testing the get saml token request. Must succeed.
     */
    @Test
    public void testGetSAMLTokenRequest() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(PEPSParameters.SAML_REQUEST.toString(),
                new String(Base64.encode(TestingConstants.SAML_TOKEN_CONS.toString().getBytes())));
        assertArrayEquals(SAML_TOKEN_ARRAY, auspepssaml.getSAMLToken(parameters,
                PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), true));
    }

    /**
     * Test method for {@link AUSPEPSSAML#getSAMLToken(Map, String, boolean)} .
     * Testing the get saml token response. Must succeed.
     */
    @Test
    public void testGetSAMLTokenResponse() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(PEPSParameters.SAML_RESPONSE.toString(),
                new String(Base64.encode(TestingConstants.SAML_TOKEN_CONS.toString().getBytes())));
        assertArrayEquals(SAML_TOKEN_ARRAY, auspepssaml.getSAMLToken(parameters,
                PEPSErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), false));
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationRequest(byte[], Map)} . Testing a
     * null saml token. Must throw a {@link InternalErrorPEPSException}.
     */
    @Test(expected = InternalErrorPEPSException.class)
    public void testProcessAuthenticationRequestInvalidSaml() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();

        final Map<String, String> mockParamaters = mock(Map.class);

        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());

        auspepssaml.processAuthenticationRequest(new byte[0], mockParamaters);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationRequest(byte[], Map)} . Testing an
     * invalid alias. Must throw a {@link SecurityPEPSException}.
     */
    @Test(expected = SecurityPEPSException.class)
    public void testProcessAuthenticationRequestInvalidAlias() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final Map<String, String> mockParamaters = mock(Map.class);

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.flushReplayCache();
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                        + PEPSValues.VALIDATION_SUFFIX.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        auspepsutil.setConfigs(CONFIGS);

        auspepssaml.setSpepsUtil(auspepsutil);
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.processAuthenticationRequest(
                generateSAMLRequest(TestingConstants.PROVIDERNAME_CERT_CONS.toString(),
                        false), mockParamaters);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationRequest(byte[], Map)} . Testing an
     * invalid SP Id. Must throw a {@link InvalidParameterPEPSException}.
     */
    @Test(expected = InvalidParameterPEPSException.class)
    public void testProcessAuthenticationRequestInvalidSp() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final Map<String, String> mockParamaters = mock(Map.class);

        when(mockParamaters.get(PEPSParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + PEPSValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(PEPSParameters.PEPS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        auspepsutil.setConfigs(configs);

        auspepssaml.setSpepsUtil(auspepsutil);
        auspepsutil.flushReplayCache();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.processAuthenticationRequest(
                generateSAMLRequest("local-demo-cert", false), mockParamaters);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationRequest(byte[], Map)} . Testing an
     * invalid SP Id with Citizen country set on the saml token. Must throw a
     * {@link InvalidParameterPEPSException}.
     */
    @Test(expected = InvalidParameterPEPSException.class)
    public void testProcessAuthenticationRequestInvalidSpCitizenCountry() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final Map<String, String> mockParamaters = mock(Map.class);

        when(mockParamaters.get(PEPSParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + PEPSValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(PEPSParameters.PEPS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        auspepsutil.setConfigs(configs);

        auspepssaml.setSpepsUtil(auspepsutil);
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.processAuthenticationRequest(
                generateSAMLRequest("local-demo-cert", true), mockParamaters);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationRequest(byte[], Map)} . Testing
     * with not allowed attributes to the SP. Must throw a
     * {@link InternalErrorPEPSException}.
     */
    @Test(expected = SecurityPEPSException.class)
    public void testProcessAuthenticationRequestInvalidContents() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final Map<String, String> mockParameters = mock(Map.class);

        when(mockParameters.get(PEPSParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());
        when(mockParameters.get(PEPSParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.QAALEVEL_CONS.toString());
        when(mockParameters.get(PEPSParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + PEPSValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(PEPSParameters.PEPS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        configs.put(TestingConstants.SPID_CONS.getQaaLevel(),
                TestingConstants.QAALEVEL_CONS.toString());
        configs.put(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auspepsutil.setConfigs(configs);

        auspepsutil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auspepsutil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());
        auspepssaml.setSpepsUtil(auspepsutil);
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        byte b[]=generateSAMLRequest("local-demo-cert", true);
        String request=new String(b, Charset.forName("UTF-8"));
        auspepssaml.processAuthenticationRequest(b, mockParameters);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationRequest(byte[], Map)} . Must
     * succeed.
     */
    @Test
    public void testProcessAuthenticationRequest() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);

        final Map<String, String> mockParameters = mock(Map.class);
        when(mockParameters.get(PEPSParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());
        when(mockParameters.get(PEPSParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.QAALEVEL_CONS.toString());
        when(mockParameters.get(PEPSParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        auspepsUtil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsUtil.setAntiReplayCache(auspepsUtil.getConcurrentMapService().getNewAntiReplayCache());
        auspepsUtil.flushReplayCache();

        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + PEPSValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(PEPSParameters.PEPS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        configs.put(TestingConstants.SPID_CONS.getQaaLevel(),
                TestingConstants.QAALEVEL_CONS.toString());
        configs.put(PEPSValues.DEFAULT.toString(),
                TestingConstants.ALL_CONS.toString());
        auspepsUtil.setConfigs(configs);

        auspepsUtil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auspepsUtil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());
        auspepssaml.setSpepsUtil(auspepsUtil);
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.setLoggerBean(mockLoggerBean);

        auspepssaml.processAuthenticationRequest(
                generateSAMLRequest("local-demo-cert", false), mockParameters);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateSpAuthnRequest(STORKAuthnRequest)} . Testing
     * with an empty {@link STORKAuthnRequest} object. Must throw a
     * {@link InternalErrorPEPSException}.
     */
    @Test(expected = InternalErrorPEPSException.class)
    public void testGenerateSpAuthnRequestInvalidAuthData() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        setPropertyForAllMessageFormatSupport(auspepssaml);
        auspepssaml.generateSpAuthnRequest(authData);

    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateSpAuthnRequest(STORKAuthnRequest)} . Must
     * Succeed.
     */
    @Test
    public void testGenerateSpAuthnRequest() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        setPropertyForAllMessageFormatSupport(auspepssaml);
        auspepssaml.generateSpAuthnRequest(authData);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateCpepsAuthnRequest(STORKAuthnRequest)} . Testing
     * with an empty {@link STORKAuthnRequest} object. Must throw a
     * {@link InternalErrorPEPSException}.
     */
    @Test(expected = InternalErrorPEPSException.class)
    public void testGenerateCpepsAuthnRequestInvalidAuthData() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        setPropertyForAllMessageFormatSupport(auspepssaml);
        auspepssaml.generateCpepsAuthnRequest(authData);
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateCpepsAuthnRequest(STORKAuthnRequest)} . Must
     * Succeed.
     */
    @Test
    public void testGenerateCpepsAuthnRequest() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        setPropertyForAllMessageFormatSupport(auspepssaml);
        final STORKAuthnRequest authReq =
                auspepssaml.generateCpepsAuthnRequest(authData);
        assertSame(authReq.getAssertionConsumerServiceURL(),
                authData.getAssertionConsumerServiceURL());
        assertSame(authReq.getIssuer(), authData.getIssuer());
        assertNotSame(authReq.getSamlId(), authData.getSamlId());
        //Qaa not used with eidas Format
//        assertSame(authReq.getQaa(), authData.getQaa());
        assertSame(authReq.getProviderName(), authData.getProviderName());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationResponse(byte[], STORKAuthnRequest, STORKAuthnRequest, String)}
     * . Testing with an empty {@link STORKAuthnRequest} object. Must throw a
     * {@link InternalErrorPEPSException}.
     */
    @Test(expected = InternalErrorPEPSException.class)
    public void testProcessAuthenticationResponseInvalidSamlToken() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS + PEPSValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(PEPSParameters.PEPS_NUMBER.toString(), TestingConstants.ONE_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.index(1), TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.name(1), TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.url(1), TestingConstants.LOCAL_URL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.skew(1), TestingConstants.SKEW_ZERO_CONS.toString());
        auspepsutil.setConfigs(configs);
        auspepssaml.setSpepsUtil(auspepsutil);

        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS.toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        final STORKAuthnRequest spAuthData = new STORKAuthnRequest();
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.processAuthenticationResponse(new byte[0], authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationResponse(byte[], STORKAuthnRequest, STORKAuthnRequest, String)}
     * . Testing with an invalid SAML ID (stored inResponseTo and saml response id
     * doesn't match). Must throw a {@link InvalidSessionPEPSException}.
     */
    @Test(expected = InvalidSessionPEPSException.class)
    public void testProcessAuthenticationResponseInvalidRespId() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        final AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS+ PEPSValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(PEPSParameters.PEPS_NUMBER.toString(),TestingConstants.ONE_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.index(1),TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.name(1),TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.url(1),TestingConstants.LOCAL_URL_CONS.toString());
        configs.setProperty(PEPSValues.CPEPS_PREFIX.skew(1),TestingConstants.SKEW_ZERO_CONS.toString());
        auspepsutil.setConfigs(configs);

        auspepssaml.setSpepsUtil(auspepsutil);
        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS.toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        final STORKAuthnRequest spAuthData = new STORKAuthnRequest();

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());

        auspepssaml.processAuthenticationResponse(
                generateSAMLResponse(TestingConstants.SAML_ID_CONS.toString(), true),
                authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationResponse(byte[], STORKAuthnRequest, STORKAuthnRequest, String)}
     * . Testing with missing SAML engine data. Must throw a
     * {@link InternalErrorPEPSException}.
     */
    @Test(expected = InternalErrorPEPSException.class)
    public void testProcessAuthenticationResponseSamlError() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();

        final AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        auspepsUtil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsUtil.setAntiReplayCache(auspepsUtil.getConcurrentMapService().getNewAntiReplayCache());
        auspepsUtil.flushReplayCache();


        auspepssaml.setSpepsUtil(auspepsUtil);
        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        final STORKAuthnRequest spAuthData = new STORKAuthnRequest();

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());

        final MessageSource mockMessages = mock(MessageSource.class);
        when(mockMessages.getMessage(anyString(), (Object[]) any(), (Locale) any()))
                .thenReturn("003002 - Authentication Failed.");

        auspepssaml.setMessageSource(mockMessages);

        auspepssaml.processAuthenticationResponse(
                generateSAMLResponse(TestingConstants.SAML_ID_CONS.toString(), true),
                authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationResponse(byte[], STORKAuthnRequest, STORKAuthnRequest, String)}
     * . Testing with wrong saml's audience data. Must throw a
     * {@link InvalidSessionPEPSException}.
     */
    @Test(expected = InvalidSessionPEPSException.class)
    public void testProcessAuthenticationResponseInvalidAudience() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();

        final AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        auspepsUtil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsUtil.setAntiReplayCache(auspepsUtil.getConcurrentMapService().getNewAntiReplayCache());
        auspepsUtil.flushReplayCache();
        final Properties configs = new Properties();
        configs.put(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auspepsUtil.setConfigs(configs);
        auspepssaml.setSpepsUtil(auspepsUtil);
        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        final STORKAuthnRequest spAuthData = new STORKAuthnRequest();

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        auspepssaml.processAuthenticationResponse(
                generateSAMLResponse(TestingConstants.SAML_ID_CONS.toString(), false),
                authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#processAuthenticationResponse(byte[], STORKAuthnRequest, STORKAuthnRequest, String)}
     * . Must Succeed.
     */
    @Test
    public void testProcessAuthenticationResponse() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();

        final AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        auspepsUtil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auspepsUtil.setAntiReplayCache(auspepsUtil.getConcurrentMapService().getNewAntiReplayCache());
        auspepsUtil.flushReplayCache();

        final Properties configs = new Properties();
        configs.put(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auspepsUtil.setConfigs(configs);

        auspepssaml.setSpepsUtil(auspepsUtil);
        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        final STORKAuthnRequest spAuthData = new STORKAuthnRequest();

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        final STORKAuthnRequest authResp =
                auspepssaml.processAuthenticationResponse(
                        generateSAMLResponse(TestingConstants.SAML_ID_CONS.toString(), false),
                        authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
        assertSame(authResp.getAssertionConsumerServiceURL(),
                authData.getAssertionConsumerServiceURL());
        assertSame(authResp.getIssuer(), authData.getIssuer());
        assertSame(authResp.getSamlId(), authData.getSamlId());
        assertSame(authResp.getQaa(), authData.getQaa());
        assertSame(authResp.getProviderName(), authData.getProviderName());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateAuthenticationResponse(STORKAuthnRequest, String)}
     * . Testing with empty {@link STORKAuthnRequest} object. Must throw an
     * {@link InternalErrorPEPSException}.
     */
    @Test(expected = InternalErrorPEPSException.class)
    public void testGenerateAuthenticationResponseInvalidAuthData() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        setPropertyForAllMessageFormatSupport(auspepssaml);
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        auspepssaml.generateAuthenticationResponse(authData,
                TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUSPEPSSAML#generateAuthenticationResponse(STORKAuthnRequest, String)}
     * . Must Succeed.
     */
    @Test
    public void testGenerateAuthenticationResponse() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        setPropertyForAllMessageFormatSupport(auspepssaml);
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());

        assertTrue(auspepssaml.generateAuthenticationResponse(authData,
                TestingConstants.USER_IP_CONS.toString()).length > 0);
    }

    /**
     * In order to test the
     * {@link AUSPEPSSAML#processAuthenticationResponse(byte[], STORKAuthnRequest, STORKAuthnRequest, String)}
     * a SAML must be generated.
     *
     * @param samlId  The SAML Id.
     * @param isError True if it's to generate an error SAML response or succeed
     *                authentication SAML otherwise.
     * @return The SAML response.
     */
    private static byte[] generateSAMLResponse(final String samlId,
                                               final boolean isError) {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());

        AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        configs.put(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auspepsUtil.setConfigs(configs);
        auspepssaml.setSpepsUtil(auspepsUtil);

        if (isError) {
            final String errorCode = "003002";
            final String errorMessage = "003002 - Authentication Failed.";
            return auspepssaml.generateErrorAuthenticationResponse(samlId,
                    TestingConstants.SAML_ISSUER_CONS.toString(),
                    TestingConstants.DESTINATION_CONS.toString(),
                    TestingConstants.USER_IP_CONS.toString(), errorCode,
                    StatusCode.AUTHN_FAILED_URI, errorMessage);
        } else {
            final STORKAuthnRequest authData = new STORKAuthnRequest();
            authData.setPersonalAttributeList(ATTR_LIST);
            authData
                    .setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                            .toString());
            authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
            authData.setSamlId(samlId);
            authData.setTokenSaml(SAML_TOKEN_ARRAY);
            authData.setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS
                    .toString());
            authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());
            return auspepssaml.generateAuthenticationResponse(authData,
                    TestingConstants.USER_IP_CONS.toString());
        }
    }

    /**
     * In order to test the
     * {@link AUSPEPSSAML#generateSpAuthnRequest(STORKAuthnRequest)} a saml must
     * be generated.
     *
     * @return The Saml request.
     */
    private static byte[] generateSAMLRequest(final String providerName,
                                              final boolean setCountry) {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);

        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS.toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData.setProviderName(providerName);
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());
        authData.setSPID(TestingConstants.SPID_CONS.toString());
        authData.setDestination(TestingConstants.DESTINATION_CONS.toString());
        authData.setMessageFormatName("stork1");
        if (setCountry) {
            authData.setCitizenCountryCode(TestingConstants.LOCAL_CONS.toString());
        }
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        final Properties configs = new Properties();
        configs.put(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        auspepsutil.setConfigs(configs);
        auspepssaml.setSpepsUtil(auspepsutil);
        return auspepssaml.generateSpAuthnRequest(authData).getTokenSaml();
    }

    /**
     * Test method for
     * {@link eu.stork.peps.auth.speps.AUSPEPSSAML#getMetadata()} (STORKAuthnRequest, String)}
     * . Testing with empty {@link STORKAuthnRequest} object. Must throw an
     * {@link InternalErrorPEPSException}.
     */
    //@Test(expected = InternalErrorPEPSException.class)
    @Test
    public void testGenerateMetadata() {
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS.toString());
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());
        String metadata = auspepssaml.getMetadata();
        System.out.println(metadata);
        assertNotNull(metadata);
    }

    /**
     * test the EIDIAS only mode cause an error when trying to generate CPEPS authn request
     */
    @Test(expected = InvalidParameterPEPSException.class )
    public void testGenerateStorkSAMLRequestInEidasOnlyMode(){
        final AUSPEPSSAML auspepssaml = new AUSPEPSSAML();
        auspepssaml.setSamlCpepsInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final STORKAuthnRequest authData = new STORKAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());

        final IStorkLogger mockLoggerBean = mock(IStorkLogger.class);
        auspepssaml.setLoggerBean(mockLoggerBean);
        auspepssaml.setStorkSAMLEngineFactory(new StorkSAMLEngineFactory());

        AUSPEPSUtil auspepsutil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        // Support to eIDAS message format only
        configs.put(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "true");
        auspepsutil.setConfigs(configs);
        auspepssaml.setSpepsUtil(auspepsutil);

        final STORKAuthnRequest authReq = auspepssaml.generateCpepsAuthnRequest(authData);
        assertNotNull(authReq);
    }

    private void setPropertyForAllMessageFormatSupport(AUSPEPSSAML auspepssaml){
        AUSPEPSUtil auspepsUtil = new AUSPEPSUtil();
        final Properties configs = new Properties();
        configs.put(PEPSValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auspepsUtil.setConfigs(configs);
        auspepssaml.setSpepsUtil(auspepsUtil);
    }

}
