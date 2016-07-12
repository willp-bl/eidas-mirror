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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.eidas.auth.commons.Country;
import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.InvalidSessionEIDASException;
import eu.eidas.node.auth.connector.AUCONNECTOR;
import eu.eidas.node.auth.connector.ICONNECTORCountrySelectorService;
import eu.eidas.node.auth.connector.ICONNECTORSAMLService;
import eu.eidas.node.auth.connector.ICONNECTORTranslatorService;
import eu.eidas.node.auth.util.tests.TestingConstants;

/**
 * Functional testing class to {@link AUCONNECTOR}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUCONNECTORTestCase {
  
  /**
   * Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList ATTR_LIST = new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList NATIVE_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Properties values for testing proposes.
   */
  private static Properties CONFIGS = new Properties();
  
  /**
   * Country List dummy values for testing proposes.
   */
  private static List<Country> COUNTRY_LIST = new ArrayList<Country>(1);
  
  /**
   * byte[] dummy SAML token.
   */
  private static byte[] SAML_TOKEN_ARRAY = new byte[] { 1, 23, -86, -71, -21,
    45, 0, 0, 0, 3, -12, 94, -86, -25, -84, 122, -53, 64 };
  
  /**
   * byte[] dummy Native SAML token.
   */
  private static byte[] SAML_NATIVE_TOKEN_ARRAY = new byte[] { 1, 23, 86, 71,
    21, 45, 0, 0, 0, 3, 12, 94, 86, 25, 84, 122, 53, 64 };
  
  /**
   * Initialising class variables.
   * 
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void runBeforeClass() throws Exception {
    COUNTRY_LIST.add(new Country(TestingConstants.LOCAL_CONS.toString(),
      TestingConstants.LOCAL_CONS.toString()));
    
    CONFIGS.put(EIDASErrors.INVALID_SESSION.errorCode(),
      TestingConstants.ERROR_CODE_CONS);
    CONFIGS.put(EIDASErrors.INVALID_SESSION.errorMessage(),
      TestingConstants.ERROR_MESSAGE_CONS);
    EIDASUtil.createInstance(CONFIGS);
    
    ATTR_LIST.populate("age:true:[15,]:Available;");
    NATIVE_ATTR_LIST.populate("idade:true:[15,]:Available;");
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#processCountrySelector(java.util.Map)}
   * . Testing with missing SP Information. Must Succeed.
   */
  @Test
  public void testProcessCountrySelectorMissingSPInfo() {
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    final ICONNECTORCountrySelectorService mockCountrySelService =
      mock(ICONNECTORCountrySelectorService.class);
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setTokenSaml(SAML_TOKEN_ARRAY);
    when(
      mockCountrySelService.checkCountrySelectorRequest(
        (Map<String, String>) any(), (ICONNECTORSAMLService) any())).thenReturn(
      authData);
    
    auconnector.setSpApplication(TestingConstants.SP_APPLICATION_CONS.toString());
    auconnector.setSpInstitution(TestingConstants.SP_INSTITUTION_CONS.toString());
    auconnector.setSpCountry(TestingConstants.LOCAL_CONS.toString());
    auconnector.setSpSector(TestingConstants.SP_SECTOR_CONS.toString());
    
    final ICONNECTORSAMLService mockSamlService = mock(ICONNECTORSAMLService.class);
    
    when(mockSamlService.generateSpAuthnRequest((EIDASAuthnRequest) any()))
      .thenReturn(authData);
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    auconnector.setSamlService(mockSamlService);
    auconnector.setCountryService(mockCountrySelService);
    assertArrayEquals(SAML_TOKEN_ARRAY,
      auconnector.processCountrySelector(mockParameters));
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#processCountrySelector(java.util.Map)}
   * . Must Succeed.
   */
  @Test
  public void testProcessCountrySelector() {
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    final ICONNECTORCountrySelectorService mockCountrySelService =
      mock(ICONNECTORCountrySelectorService.class);
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setTokenSaml(SAML_TOKEN_ARRAY);
    authData.setSPID(TestingConstants.SPID_CONS.toString());
    authData.setSpApplication(TestingConstants.SP_APPLICATION_CONS.toString());
    authData.setSpInstitution(TestingConstants.SP_INSTITUTION_CONS.toString());
    authData.setSpCountry(TestingConstants.LOCAL_CONS.toString());
    authData.setSpSector(TestingConstants.SP_SECTOR_CONS.toString());
    
    when(
      mockCountrySelService.checkCountrySelectorRequest(
        (Map<String, String>) any(), (ICONNECTORSAMLService) any())).thenReturn(
      authData);
    
    final ICONNECTORSAMLService mockSamlService = mock(ICONNECTORSAMLService.class);
    
    when(mockSamlService.generateSpAuthnRequest((EIDASAuthnRequest) any()))
      .thenReturn(authData);
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    auconnector.setSamlService(mockSamlService);
    auconnector.setCountryService(mockCountrySelService);
    assertArrayEquals(SAML_TOKEN_ARRAY,
      auconnector.processCountrySelector(mockParameters));
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#getCountrySelectorList()}. Must
   * Succeed.
   */
  @Test
  public void testGetCountrySelectorList() {
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    final ICONNECTORCountrySelectorService mockCountrySelService =
      mock(ICONNECTORCountrySelectorService.class);
    when(mockCountrySelService.createCountrySelector())
      .thenReturn(COUNTRY_LIST);
    
    auconnector.setCountryService(mockCountrySelService);
    assertArrayEquals(COUNTRY_LIST.toArray(), auconnector.getCountrySelectorList()
      .toArray());
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#getAuthenticationRequest(java.util.Map, eu.eidas.auth.commons.IEIDASSession)}
   * . Must Succeed.
   */
  @Test
  public void testGetAuthenticationRequestMissingRelay() {
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    final Map<String, String> mockParameters = mock(Map.class);
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    final ICONNECTORSAMLService mockSamlService = mock(ICONNECTORSAMLService.class);
    final ICONNECTORTranslatorService mockTranslatorService =
      mock(ICONNECTORTranslatorService.class);
    
    when(mockParameters.get(EIDASParameters.RELAY_STATE.toString())).thenReturn(
      TestingConstants.SP_RELAY_STATE_CONS.toString());
    when(mockParameters.get(EIDASParameters.ASSERTION_CONSUMER_S_URL.toString()))
      .thenReturn(TestingConstants.ASSERTION_URL_CONS.toString());
    
    when(mockSamlService.getSAMLToken(anyMap(), anyString(), anyBoolean()))
      .thenReturn(SAML_TOKEN_ARRAY);
    when(
      mockSamlService.processAuthenticationRequest(SAML_TOKEN_ARRAY,
        mockParameters)).thenReturn(authData);
    when(mockSamlService.generateServiceAuthnRequest((EIDASAuthnRequest) any()))
      .thenReturn(authData);
    
    when(mockTranslatorService.normaliseAttributeNamesToFormat(ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auconnector.setSamlService(mockSamlService);
    auconnector.setTransService(mockTranslatorService);
    assertEquals(NATIVE_ATTR_LIST.toString(),
      auconnector.getAuthenticationRequest(mockParameters, mockSession)
        .getPersonalAttributeList().toString());
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#getAuthenticationRequest(java.util.Map, eu.eidas.auth.commons.IEIDASSession)}
   * . Must Succeed.
   */
  @Test
  public void testGetAuthenticationRequest() {
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    final Map<String, String> mockParameters = mock(Map.class);
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    final ICONNECTORSAMLService mockSamlService = mock(ICONNECTORSAMLService.class);
    final ICONNECTORTranslatorService mockTranslatorService =
      mock(ICONNECTORTranslatorService.class);
    
    when(mockParameters.get(EIDASParameters.ASSERTION_CONSUMER_S_URL.toString()))
      .thenReturn(TestingConstants.ASSERTION_URL_CONS.toString());
    
    when(mockSamlService.getSAMLToken(anyMap(), anyString(), anyBoolean()))
      .thenReturn(SAML_TOKEN_ARRAY);
    when(
      mockSamlService.processAuthenticationRequest(SAML_TOKEN_ARRAY,
        mockParameters)).thenReturn(authData);
    when(mockSamlService.generateServiceAuthnRequest((EIDASAuthnRequest) any()))
      .thenReturn(authData);
    
    when(mockTranslatorService.normaliseAttributeNamesToFormat(ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auconnector.setSamlService(mockSamlService);
    auconnector.setTransService(mockTranslatorService);
    assertEquals(NATIVE_ATTR_LIST.toString(),
      auconnector.getAuthenticationRequest(mockParameters, mockSession)
        .getPersonalAttributeList().toString());
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#getAuthenticationResponse(java.util.Map, eu.eidas.auth.commons.IEIDASSession)}
   * . Testing invalid session data. Must throw and
   * {@link InvalidSessionEIDASException}.
   */
  @Test(expected = InvalidSessionEIDASException.class)
  public void testGetAuthenticationResponseInvalidSession() {
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    when(mockSession.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    auconnector.getAuthenticationResponse(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#getAuthenticationResponse(java.util.Map, eu.eidas.auth.commons.IEIDASSession)}
   * . Must succeed.
   */
  @Test
  public void testGetAuthenticationResponse() {
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
    
    final EIDASAuthnRequest spAuthData = new EIDASAuthnRequest();
    spAuthData
      .setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
        .toString());
    spAuthData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
    spAuthData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
    
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    when(mockSession.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    when(mockSession.get(EIDASParameters.SAML_IN_RESPONSE_TO.toString()))
      .thenReturn(TestingConstants.SAML_ID_CONS.toString());
    when(mockSession.get(EIDASParameters.REMOTE_ADDR.toString())).thenReturn(
      TestingConstants.USER_IP_CONS.toString());
    when(mockSession.get(EIDASParameters.SP_URL.toString())).thenReturn(
      TestingConstants.ASSERTION_URL_CONS.toString());
    
    final ICONNECTORSAMLService mockSamlService = mock(ICONNECTORSAMLService.class);
    when(
      mockSamlService.getSAMLToken(mockParameters,
        EIDASErrors.COLLEAGUE_RESP_INVALID_SAML.name(), false)).thenReturn(
      SAML_TOKEN_ARRAY);
    
    authData.setPersonalAttributeList(ATTR_LIST);
    when(
      mockSamlService.processAuthenticationResponse((byte[]) any(),
        (EIDASAuthnRequest) any(), (EIDASAuthnRequest) any(), anyString()))
      .thenReturn(authData);
    when(
      mockSamlService.generateAuthenticationResponse((EIDASAuthnRequest) any(),
        anyString())).thenReturn(SAML_NATIVE_TOKEN_ARRAY);
    
    auconnector.setSamlService(mockSamlService);
    
    final ICONNECTORTranslatorService mockTransService =
      mock(ICONNECTORTranslatorService.class);
    when(mockTransService.normaliseAttributeNamesToFormat(ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auconnector.setTransService(mockTransService);
    
    spAuthData.setTokenSaml(NATIVE_ATTR_LIST.toString().getBytes());
    
    final EIDASAuthnRequest authResp =
      auconnector.getAuthenticationResponse(mockParameters, mockSession);
    assertSame(spAuthData.getAssertionConsumerServiceURL(),
      authResp.getAssertionConsumerServiceURL());
    assertSame(spAuthData.getIssuer(), authResp.getIssuer());
    assertSame(spAuthData.getSamlId(), authResp.getSamlId());
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#sendRedirect(byte[])}. Testing null
   * value. Must throw {@link NullPointerException}.
   */
  @Test(expected = NullPointerException.class)
  public void testSendRedirectNullToken() {
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    auconnector.sendRedirect(null);
  }
  
  /**
   * Test method for
   * {@link eu.eidas.node.auth.connector.AUCONNECTOR#sendRedirect(byte[])}. Must
   * succeed.
   */
  @Test
  public void testSendRedirect() {
    final AUCONNECTOR auconnector = new AUCONNECTOR();
    assertEquals("ARequestAAAAA/RequesestA",
      auconnector.sendRedirect(SAML_TOKEN_ARRAY));
  }
}
