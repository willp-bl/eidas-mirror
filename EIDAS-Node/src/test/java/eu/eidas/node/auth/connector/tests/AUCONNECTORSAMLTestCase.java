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
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASLogger;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.node.auth.ConcurrentMapServiceDefaultImpl;
import eu.eidas.node.auth.connector.AUCONNECTORSAML;
import eu.eidas.node.auth.connector.AUCONNECTORUtil;
import eu.eidas.node.auth.connector.ICONNECTORSAMLService;
import eu.eidas.node.auth.util.tests.TestingConstants;
import eu.eidas.node.init.EidasSamlEngineFactory;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml2.core.StatusCode;
import org.springframework.context.MessageSource;

/**
 * Functional testing class to {@link eu.eidas.node.auth.connector.AUCONNECTORCountrySelector}.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUCONNECTORSAMLTestCase {
    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUCONNECTORSAMLTestCase.class.getName());


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

        CONFIGS.setProperty(EIDASValues.HASH_DIGEST_CLASS.toString(),
                "org.bouncycastle.crypto.digests.SHA512Digest");
        CONFIGS.setProperty(EIDASParameters.VALIDATION_ACTIVE.toString(),
                TestingConstants.TRUE_CONS.toString());

        CONFIGS.setProperty("max.SAMLRequest.size", "131072");
        CONFIGS.setProperty("max.SAMLResponse.size", "131072");
        CONFIGS.setProperty("max.spUrl.size", "150");
        CONFIGS.setProperty("max.attrList.size", "20000");
        CONFIGS.setProperty("max.providerName.size", "128");
        CONFIGS.setProperty("max.spQaaLevel.size", "1");
        CONFIGS.setProperty("max.spId.size", "40");
        CONFIGS.setProperty("max.serviceRedirectUrl.size", "300");

        EIDASUtil.createInstance(CONFIGS);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#generateErrorAuthenticationResponse(String, String, String, String, String, String, String)}
     * . Testing with no instance set. Must throw and {@link NullPointerException}
     * .
     */
    @Test(expected = NullPointerException.class)
    public void testGenerateErrorAuthenticationResponseInvalidSamlInstance() {
        final ICONNECTORSAMLService auconnectorsaml = new AUCONNECTORSAML();
        ((AUCONNECTORSAML)auconnectorsaml).setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.generateErrorAuthenticationResponse(
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
     * {@link AUCONNECTORSAML#generateErrorAuthenticationResponse(String, String, String, String, String, String, String)}
     * . Testing with no Saml id that will led to a saml engine exception. Must
     * throw and {@link NullPointerException}.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testGenerateErrorAuthenticationResponseInvalidSamlData() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.generateErrorAuthenticationResponse(
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
     * {@link AUCONNECTORSAML#generateErrorAuthenticationResponse(String, String, String, String, String, String, String)}
     * . Must succeed.
     */
    @Test
    public void testGenerateErrorAuthenticationResponse() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        byte[] token = auconnectorsaml.generateErrorAuthenticationResponse(
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
     * Test method for {@link AUCONNECTORSAML#getSAMLToken(Map, String, boolean)} .
     * Testing with a null saml token. Must throw an
     * {@link InvalidParameterEIDASException}.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testGetSAMLTokenNull() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final Map<String, String> parameters = new HashMap<String, String>();
        auconnectorsaml.getSAMLToken(parameters,
                EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), true);
    }

    /**
     * Test method for {@link AUCONNECTORSAML#getSAMLToken(Map, String, boolean)} .
     * Testing the get saml token request. Must succeed.
     */
    @Test
    public void testGetSAMLTokenRequest() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(EIDASParameters.SAML_REQUEST.toString(),
                new String(Base64.encode(TestingConstants.SAML_TOKEN_CONS.toString().getBytes())));
        assertArrayEquals(SAML_TOKEN_ARRAY, auconnectorsaml.getSAMLToken(parameters,
                EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), true));
    }

    /**
     * Test method for {@link AUCONNECTORSAML#getSAMLToken(Map, String, boolean)} .
     * Testing the get saml token response. Must succeed.
     */
    @Test
    public void testGetSAMLTokenResponse() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(EIDASParameters.SAML_RESPONSE.toString(),
                new String(Base64.encode(TestingConstants.SAML_TOKEN_CONS.toString().getBytes())));
        assertArrayEquals(SAML_TOKEN_ARRAY, auconnectorsaml.getSAMLToken(parameters,
                EIDASErrors.SPROVIDER_SELECTOR_INVALID_SAML.name(), false));
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationRequest(byte[], Map)} . Testing a
     * null saml token. Must throw a {@link InternalErrorEIDASException}.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testProcessAuthenticationRequestInvalidSaml() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();

        final Map<String, String> mockParamaters = mock(Map.class);

        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());

        auconnectorsaml.processAuthenticationRequest(new byte[0], mockParamaters);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationRequest(byte[], Map)} . Testing an
     * invalid alias. Must throw a {@link SecurityEIDASException}.
     */
    @Test(expected = SecurityEIDASException.class)
    public void testProcessAuthenticationRequestInvalidAlias() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final Map<String, String> mockParamaters = mock(Map.class);

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.flushReplayCache();
        CONFIGS.put(TestingConstants.PROVIDERNAME_CONS
                        + EIDASValues.VALIDATION_SUFFIX.toString(),
                TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        auconnectorutil.setConfigs(CONFIGS);

        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.processAuthenticationRequest(
                generateSAMLRequest(TestingConstants.PROVIDERNAME_CERT_CONS.toString(),
                        false), mockParamaters);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationRequest(byte[], Map)} . Testing an
     * invalid SP Id. Must throw a {@link InvalidParameterEIDASException}.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testProcessAuthenticationRequestInvalidSp() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final Map<String, String> mockParamaters = mock(Map.class);

        when(mockParamaters.get(EIDASParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + EIDASValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        auconnectorutil.setConfigs(configs);

        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorutil.flushReplayCache();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.processAuthenticationRequest(
                generateSAMLRequest("local-demo-cert", false), mockParamaters);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationRequest(byte[], Map)} . Testing an
     * invalid SP Id with Citizen country set on the saml token. Must throw a
     * {@link InvalidParameterEIDASException}.
     */
    @Test(expected = InvalidParameterEIDASException.class)
    public void testProcessAuthenticationRequestInvalidSpCitizenCountry() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final Map<String, String> mockParamaters = mock(Map.class);

        when(mockParamaters.get(EIDASParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + EIDASValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        auconnectorutil.setConfigs(configs);

        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.processAuthenticationRequest(
                generateSAMLRequest("local-demo-cert", true), mockParamaters);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationRequest(byte[], Map)} . Testing
     * with not allowed attributes to the SP. Must throw a
     * {@link InternalErrorEIDASException}.
     */
    @Test(expected = SecurityEIDASException.class)
    public void testProcessAuthenticationRequestInvalidContents() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final Map<String, String> mockParameters = mock(Map.class);

        when(mockParameters.get(EIDASParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());
        when(mockParameters.get(EIDASParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.QAALEVEL_CONS.toString());
        when(mockParameters.get(EIDASParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + EIDASValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        configs.put(TestingConstants.SPID_CONS.getQaaLevel(),
                TestingConstants.QAALEVEL_CONS.toString());
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auconnectorutil.setConfigs(configs);

        auconnectorutil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auconnectorutil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());
        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        byte b[]=generateSAMLRequest("local-demo-cert", true);
        String request=new String(b, Charset.forName("UTF-8"));
        auconnectorsaml.processAuthenticationRequest(b, mockParameters);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationRequest(byte[], Map)} . Must
     * succeed.
     */
    @Test
    public void testProcessAuthenticationRequest() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);

        final Map<String, String> mockParameters = mock(Map.class);
        when(mockParameters.get(EIDASParameters.COUNTRY.toString())).thenReturn(
                TestingConstants.LOCAL_CONS.toString());
        when(mockParameters.get(EIDASParameters.SP_QAALEVEL.toString())).thenReturn(
                TestingConstants.QAALEVEL_CONS.toString());
        when(mockParameters.get(EIDASParameters.SP_ID.toString())).thenReturn(
                TestingConstants.SPID_CONS.toString());

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setAntiReplayCache(auconnectorutil.getConcurrentMapService().getNewAntiReplayCache());
        auconnectorutil.flushReplayCache();

        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS
                + EIDASValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),
                TestingConstants.ONE_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),
                TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.url(1),
                TestingConstants.LOCAL_URL_CONS.toString());
        configs.put(TestingConstants.SPID_CONS.getQaaLevel(),
                TestingConstants.QAALEVEL_CONS.toString());
        configs.put(EIDASValues.DEFAULT.toString(),
                TestingConstants.ALL_CONS.toString());
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(),
                TestingConstants.FALSE_CONS.toString());
        auconnectorutil.setConfigs(configs);

        auconnectorutil.setMaxQAA(TestingConstants.MAX_QAA_CONS.intValue());
        auconnectorutil.setMinQAA(TestingConstants.MIN_QAA_CONS.intValue());
        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.setLoggerBean(mockLoggerBean);

        auconnectorsaml.processAuthenticationRequest(
                generateSAMLRequest("local-demo-cert", false), mockParameters);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#generateSpAuthnRequest(EIDASAuthnRequest)} . Testing
     * with an empty {@link EIDASAuthnRequest} object. Must throw a
     * {@link InternalErrorEIDASException}.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testGenerateSpAuthnRequestInvalidAuthData() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        setPropertyForAllMessageFormatSupport(auconnectorsaml);
        auconnectorsaml.generateSpAuthnRequest(authData);

    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#generateSpAuthnRequest(EIDASAuthnRequest)} . Must
     * Succeed.
     */
    @Test
    public void testGenerateSpAuthnRequest() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        setPropertyForAllMessageFormatSupport(auconnectorsaml);
        auconnectorsaml.generateSpAuthnRequest(authData);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#generateServiceAuthnRequest(EIDASAuthnRequest)} . Testing
     * with an empty {@link EIDASAuthnRequest} object. Must throw a
     * {@link InternalErrorEIDASException}.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testGenerateServiceAuthnRequestInvalidAuthData() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        setPropertyForAllMessageFormatSupport(auconnectorsaml);
        auconnectorsaml.generateServiceAuthnRequest(authData);
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#generateServiceAuthnRequest(EIDASAuthnRequest)} . Must
     * Succeed.
     */
    @Test
    public void testGenerateServiceAuthnRequest() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        setPropertyForAllMessageFormatSupport(auconnectorsaml);
        final EIDASAuthnRequest authReq =
                auconnectorsaml.generateServiceAuthnRequest(authData);
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
     * {@link AUCONNECTORSAML#processAuthenticationResponse(byte[], EIDASAuthnRequest, EIDASAuthnRequest, String)}
     * . Testing with an empty {@link EIDASAuthnRequest} object. Must throw a
     * {@link InternalErrorEIDASException}.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testProcessAuthenticationResponseInvalidSamlToken() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS+ EIDASValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),TestingConstants.ONE_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.url(1),TestingConstants.LOCAL_URL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.skew(1),TestingConstants.SKEW_ZERO_CONS.toString());
        auconnectorutil.setConfigs(configs);
        auconnectorsaml.setConnectorUtil(auconnectorutil);

        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS.toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        final EIDASAuthnRequest spAuthData = new EIDASAuthnRequest();
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.processAuthenticationResponse(new byte[0], authData,spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationResponse(byte[], EIDASAuthnRequest, EIDASAuthnRequest, String)}
     * . Testing with an invalid SAML ID (stored inResponseTo and saml response id
     * doesn't match). Must throw a {@link InvalidSessionEIDASException}.
     */
    @Test(expected = InvalidSessionEIDASException.class)
    public void testProcessAuthenticationResponseInvalidRespId() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        configs.put(TestingConstants.PROVIDERNAME_CONS+ EIDASValues.VALIDATION_SUFFIX.toString(), "local-demo-cert");
        configs.setProperty(EIDASParameters.EIDAS_NUMBER.toString(),TestingConstants.ONE_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.index(1),TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.name(1),TestingConstants.LOCAL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.url(1),TestingConstants.LOCAL_URL_CONS.toString());
        configs.setProperty(EIDASValues.EIDAS_SERVICE_PREFIX.skew(1),TestingConstants.SKEW_ZERO_CONS.toString());
        auconnectorutil.setConfigs(configs);

        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS.toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        final EIDASAuthnRequest spAuthData = new EIDASAuthnRequest();

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());

        auconnectorsaml.processAuthenticationResponse(
                generateSAMLResponse(TestingConstants.SAML_ID_CONS.toString(), true),
                authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationResponse(byte[], EIDASAuthnRequest, EIDASAuthnRequest, String)}
     * . Testing with missing SAML engine data. Must throw a
     * {@link InternalErrorEIDASException}.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testProcessAuthenticationResponseSamlError() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setAntiReplayCache(auconnectorutil.getConcurrentMapService().getNewAntiReplayCache());
        auconnectorutil.flushReplayCache();


        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        final EIDASAuthnRequest spAuthData = new EIDASAuthnRequest();

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());

        final MessageSource mockMessages = mock(MessageSource.class);
        when(mockMessages.getMessage(anyString(), (Object[]) any(), (Locale) any()))
                .thenReturn("003002 - Authentication Failed.");

        auconnectorsaml.setMessageSource(mockMessages);

        auconnectorsaml.processAuthenticationResponse(
                generateSAMLResponse(TestingConstants.SAML_ID_CONS.toString(), true),
                authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationResponse(byte[], EIDASAuthnRequest, EIDASAuthnRequest, String)}
     * . Testing with wrong saml's audience data. Must throw a
     * {@link InvalidSessionEIDASException}.
     */
    @Test(expected = InvalidSessionEIDASException.class)
    public void testProcessAuthenticationResponseInvalidAudience() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setAntiReplayCache(auconnectorutil.getConcurrentMapService().getNewAntiReplayCache());
        auconnectorutil.flushReplayCache();
        final Properties configs = new Properties();
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auconnectorutil.setConfigs(configs);

        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        final EIDASAuthnRequest spAuthData = new EIDASAuthnRequest();

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        auconnectorsaml.processAuthenticationResponse(
                generateSAMLResponse(TestingConstants.SAML_ID_CONS.toString(), false),
                authData, spAuthData, TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#processAuthenticationResponse(byte[], EIDASAuthnRequest, EIDASAuthnRequest, String)}
     * . Must Succeed.
     */
    @Test
    public void testProcessAuthenticationResponse() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();

        final AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConcurrentMapService(new ConcurrentMapServiceDefaultImpl());
        auconnectorutil.setAntiReplayCache(auconnectorutil.getConcurrentMapService().getNewAntiReplayCache());
        auconnectorutil.flushReplayCache();
        final Properties configs = new Properties();
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auconnectorutil.setConfigs(configs);

        auconnectorsaml.setConnectorUtil(auconnectorutil);
        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        final EIDASAuthnRequest spAuthData = new EIDASAuthnRequest();

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        final EIDASAuthnRequest authResp =
                auconnectorsaml.processAuthenticationResponse(
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
     * {@link AUCONNECTORSAML#generateAuthenticationResponse(EIDASAuthnRequest, String)}
     * . Testing with empty {@link EIDASAuthnRequest} object. Must throw an
     * {@link InternalErrorEIDASException}.
     */
    @Test(expected = InternalErrorEIDASException.class)
    public void testGenerateAuthenticationResponseInvalidAuthData() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        setPropertyForAllMessageFormatSupport(auconnectorsaml);
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        auconnectorsaml.generateAuthenticationResponse(authData,
                TestingConstants.USER_IP_CONS.toString());
    }

    /**
     * Test method for
     * {@link AUCONNECTORSAML#generateAuthenticationResponse(EIDASAuthnRequest, String)}
     * . Must Succeed.
     */
    @Test
    public void testGenerateAuthenticationResponse() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        setPropertyForAllMessageFormatSupport(auconnectorsaml);
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());

        assertTrue(auconnectorsaml.generateAuthenticationResponse(authData,
                TestingConstants.USER_IP_CONS.toString()).length > 0);
    }

    /**
     * In order to test the
     * {@link AUCONNECTORSAML#processAuthenticationResponse(byte[], EIDASAuthnRequest, EIDASAuthnRequest, String)}
     * a SAML must be generated.
     *
     * @param samlId  The SAML Id.
     * @param isError True if it's to generate an error SAML response or succeed
     *                authentication SAML otherwise.
     * @return The SAML response.
     */
    private static byte[] generateSAMLResponse(final String samlId,
                                               final boolean isError) {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        AUCONNECTORUtil auconnectorUtil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auconnectorUtil.setConfigs(configs);
        auconnectorsaml.setConnectorUtil(auconnectorUtil);
        if (isError) {
            final String errorCode = "003002";
            final String errorMessage = "003002 - Authentication Failed.";
            return auconnectorsaml.generateErrorAuthenticationResponse(samlId,
                    TestingConstants.SAML_ISSUER_CONS.toString(),
                    TestingConstants.DESTINATION_CONS.toString(),
                    TestingConstants.USER_IP_CONS.toString(), errorCode,
                    StatusCode.AUTHN_FAILED_URI, errorMessage);
        } else {
            final EIDASAuthnRequest authData = new EIDASAuthnRequest();
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
            return auconnectorsaml.generateAuthenticationResponse(authData,
                    TestingConstants.USER_IP_CONS.toString());
        }
    }

    /**
     * In order to test the
     * {@link AUCONNECTORSAML#generateSpAuthnRequest(EIDASAuthnRequest)} a saml must
     * be generated.
     *
     * @return The Saml request.
     */
    private static byte[] generateSAMLRequest(final String providerName,
                                              final boolean setCountry) {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);

        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
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
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        final Properties configs = new Properties();
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        auconnectorutil.setConfigs(configs);
        auconnectorsaml.setConnectorUtil(auconnectorutil);
        return auconnectorsaml.generateSpAuthnRequest(authData).getTokenSaml();
    }

    /**
     * Test method for
     * {@link eu.eidas.node.auth.connector.AUCONNECTORSAML#getMetadata()} (EIDASAuthnRequest, String)}
     * . Testing with empty {@link EIDASAuthnRequest} object. Must throw an
     * {@link InternalErrorEIDASException}.
     */
    //@Test(expected = InternalErrorNodeException.class)
    @Test
    public void testGenerateMetadata() {
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlSpInstance(TestingConstants.SAML_INSTANCE_CONS.toString());
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());
        String metadata = auconnectorsaml.getMetadata();
        System.out.println(metadata);
        assertNotNull(metadata);
    }
    /**
     * test the EIDAS only mode cause an error when trying to generate CPEPS authn request
     */
    @Test(expected = InvalidParameterEIDASException.class )
    public void testGenerateStorkSAMLRequestInEidasOnlyMode(){
        final AUCONNECTORSAML auconnectorsaml = new AUCONNECTORSAML();
        auconnectorsaml.setSamlServiceInstance(TestingConstants.SAML_INSTANCE_CONS
                .toString());
        final EIDASAuthnRequest authData = new EIDASAuthnRequest();
        authData.setPersonalAttributeList(ATTR_LIST);
        authData.setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
                .toString());
        authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
        authData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
        authData.setTokenSaml(SAML_TOKEN_ARRAY);
        authData
                .setProviderName(TestingConstants.PROVIDERNAME_CERT_CONS.toString());
        authData.setQaa(TestingConstants.QAALEVEL_CONS.intValue());

        final IEIDASLogger mockLoggerBean = mock(IEIDASLogger.class);
        auconnectorsaml.setLoggerBean(mockLoggerBean);
        auconnectorsaml.setSamlEngineFactory(new EidasSamlEngineFactory());

        AUCONNECTORUtil auconnectorutil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        // Support to eIDAS message format only
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "true");
        auconnectorutil.setConfigs(configs);
        auconnectorsaml.setConnectorUtil(auconnectorutil);

        final EIDASAuthnRequest authReq = auconnectorsaml.generateServiceAuthnRequest(authData);
        assertNotNull(authReq);
    }

    private void setPropertyForAllMessageFormatSupport(AUCONNECTORSAML auspepssaml){
        AUCONNECTORUtil auspepsUtil = new AUCONNECTORUtil();
        final Properties configs = new Properties();
        configs.put(EIDASValues.NODE_SUPPORT_EIDAS_MESSAGE_FORMAT_ONLY.toString(), "false");
        auspepsUtil.setConfigs(configs);
        auspepssaml.setConnectorUtil(auspepsUtil);
    }
    
}
