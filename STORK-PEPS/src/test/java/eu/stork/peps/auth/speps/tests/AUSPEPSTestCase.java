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

import eu.stork.peps.auth.commons.Country;
import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.exceptions.InvalidSessionPEPSException;
import eu.stork.peps.auth.speps.AUSPEPS;
import eu.stork.peps.auth.speps.ISPEPSCountrySelectorService;
import eu.stork.peps.auth.speps.ISPEPSSAMLService;
import eu.stork.peps.auth.speps.ISPEPSTranslatorService;
import eu.stork.peps.auth.util.tests.TestingConstants;

/**
 * Functional testing class to {@link AUSPEPS}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUSPEPSTestCase {
  
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
    
    CONFIGS.put(PEPSErrors.INVALID_SESSION.errorCode(),
      TestingConstants.ERROR_CODE_CONS);
    CONFIGS.put(PEPSErrors.INVALID_SESSION.errorMessage(),
      TestingConstants.ERROR_MESSAGE_CONS);
    PEPSUtil.createInstance(CONFIGS);
    
    ATTR_LIST.populate("age:true:[15,]:Available;");
    NATIVE_ATTR_LIST.populate("idade:true:[15,]:Available;");
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#processCountrySelector(java.util.Map)}
   * . Testing with missing SP Information. Must Succeed.
   */
  @Test
  public void testProcessCountrySelectorMissingSPInfo() {
    final AUSPEPS auspeps = new AUSPEPS();
    final ISPEPSCountrySelectorService mockCountrySelService =
      mock(ISPEPSCountrySelectorService.class);
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setTokenSaml(SAML_TOKEN_ARRAY);
    when(
      mockCountrySelService.checkCountrySelectorRequest(
        (Map<String, String>) any(), (ISPEPSSAMLService) any())).thenReturn(
      authData);
    
    auspeps.setSpApplication(TestingConstants.SP_APPLICATION_CONS.toString());
    auspeps.setSpInstitution(TestingConstants.SP_INSTITUTION_CONS.toString());
    auspeps.setSpCountry(TestingConstants.LOCAL_CONS.toString());
    auspeps.setSpSector(TestingConstants.SP_SECTOR_CONS.toString());
    
    final ISPEPSSAMLService mockSamlService = mock(ISPEPSSAMLService.class);
    
    when(mockSamlService.generateSpAuthnRequest((STORKAuthnRequest) any()))
      .thenReturn(authData);
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    auspeps.setSamlService(mockSamlService);
    auspeps.setCountryService(mockCountrySelService);
    assertArrayEquals(SAML_TOKEN_ARRAY,
      auspeps.processCountrySelector(mockParameters));
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#processCountrySelector(java.util.Map)}
   * . Must Succeed.
   */
  @Test
  public void testProcessCountrySelector() {
    final AUSPEPS auspeps = new AUSPEPS();
    final ISPEPSCountrySelectorService mockCountrySelService =
      mock(ISPEPSCountrySelectorService.class);
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setTokenSaml(SAML_TOKEN_ARRAY);
    authData.setSPID(TestingConstants.SPID_CONS.toString());
    authData.setSpApplication(TestingConstants.SP_APPLICATION_CONS.toString());
    authData.setSpInstitution(TestingConstants.SP_INSTITUTION_CONS.toString());
    authData.setSpCountry(TestingConstants.LOCAL_CONS.toString());
    authData.setSpSector(TestingConstants.SP_SECTOR_CONS.toString());
    
    when(
      mockCountrySelService.checkCountrySelectorRequest(
        (Map<String, String>) any(), (ISPEPSSAMLService) any())).thenReturn(
      authData);
    
    final ISPEPSSAMLService mockSamlService = mock(ISPEPSSAMLService.class);
    
    when(mockSamlService.generateSpAuthnRequest((STORKAuthnRequest) any()))
      .thenReturn(authData);
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    auspeps.setSamlService(mockSamlService);
    auspeps.setCountryService(mockCountrySelService);
    assertArrayEquals(SAML_TOKEN_ARRAY,
      auspeps.processCountrySelector(mockParameters));
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#getCountrySelectorList()}. Must
   * Succeed.
   */
  @Test
  public void testGetCountrySelectorList() {
    final AUSPEPS auspeps = new AUSPEPS();
    final ISPEPSCountrySelectorService mockCountrySelService =
      mock(ISPEPSCountrySelectorService.class);
    when(mockCountrySelService.createCountrySelector())
      .thenReturn(COUNTRY_LIST);
    
    auspeps.setCountryService(mockCountrySelService);
    assertArrayEquals(COUNTRY_LIST.toArray(), auspeps.getCountrySelectorList()
      .toArray());
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#getAuthenticationRequest(java.util.Map, eu.stork.peps.auth.commons.IStorkSession)}
   * . Must Succeed.
   */
  @Test
  public void testGetAuthenticationRequestMissingRelay() {
    final AUSPEPS auspeps = new AUSPEPS();
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    final Map<String, String> mockParameters = mock(Map.class);
    final IStorkSession mockSession = mock(IStorkSession.class);
    final ISPEPSSAMLService mockSamlService = mock(ISPEPSSAMLService.class);
    final ISPEPSTranslatorService mockTranslatorService =
      mock(ISPEPSTranslatorService.class);
    
    when(mockParameters.get(PEPSParameters.RELAY_STATE.toString())).thenReturn(
      TestingConstants.SP_RELAY_STATE_CONS.toString());
    when(mockParameters.get(PEPSParameters.ASSERTION_CONSUMER_S_URL.toString()))
      .thenReturn(TestingConstants.ASSERTION_URL_CONS.toString());
    
    when(mockSamlService.getSAMLToken(anyMap(), anyString(), anyBoolean()))
      .thenReturn(SAML_TOKEN_ARRAY);
    when(
      mockSamlService.processAuthenticationRequest(SAML_TOKEN_ARRAY,
        mockParameters)).thenReturn(authData);
    when(mockSamlService.generateCpepsAuthnRequest((STORKAuthnRequest) any()))
      .thenReturn(authData);
    
    when(mockTranslatorService.normaliseAttributeNamesToStork(ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auspeps.setSamlService(mockSamlService);
    auspeps.setTransService(mockTranslatorService);
    assertEquals(NATIVE_ATTR_LIST.toString(),
      auspeps.getAuthenticationRequest(mockParameters, mockSession)
        .getPersonalAttributeList().toString());
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#getAuthenticationRequest(java.util.Map, eu.stork.peps.auth.commons.IStorkSession)}
   * . Must Succeed.
   */
  @Test
  public void testGetAuthenticationRequest() {
    final AUSPEPS auspeps = new AUSPEPS();
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    final Map<String, String> mockParameters = mock(Map.class);
    final IStorkSession mockSession = mock(IStorkSession.class);
    final ISPEPSSAMLService mockSamlService = mock(ISPEPSSAMLService.class);
    final ISPEPSTranslatorService mockTranslatorService =
      mock(ISPEPSTranslatorService.class);
    
    when(mockParameters.get(PEPSParameters.ASSERTION_CONSUMER_S_URL.toString()))
      .thenReturn(TestingConstants.ASSERTION_URL_CONS.toString());
    
    when(mockSamlService.getSAMLToken(anyMap(), anyString(), anyBoolean()))
      .thenReturn(SAML_TOKEN_ARRAY);
    when(
      mockSamlService.processAuthenticationRequest(SAML_TOKEN_ARRAY,
        mockParameters)).thenReturn(authData);
    when(mockSamlService.generateCpepsAuthnRequest((STORKAuthnRequest) any()))
      .thenReturn(authData);
    
    when(mockTranslatorService.normaliseAttributeNamesToStork(ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auspeps.setSamlService(mockSamlService);
    auspeps.setTransService(mockTranslatorService);
    assertEquals(NATIVE_ATTR_LIST.toString(),
      auspeps.getAuthenticationRequest(mockParameters, mockSession)
        .getPersonalAttributeList().toString());
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#getAuthenticationResponse(java.util.Map, eu.stork.peps.auth.commons.IStorkSession)}
   * . Testing invalid session data. Must throw and
   * {@link InvalidSessionPEPSException}.
   */
  @Test(expected = InvalidSessionPEPSException.class)
  public void testGetAuthenticationResponseInvalidSession() {
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    
    final AUSPEPS auspeps = new AUSPEPS();
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    when(mockSession.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    auspeps.getAuthenticationResponse(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#getAuthenticationResponse(java.util.Map, eu.stork.peps.auth.commons.IStorkSession)}
   * . Must succeed.
   */
  @Test
  public void testGetAuthenticationResponse() {
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
    
    final STORKAuthnRequest spAuthData = new STORKAuthnRequest();
    spAuthData
      .setAssertionConsumerServiceURL(TestingConstants.ASSERTION_URL_CONS
        .toString());
    spAuthData.setSamlId(TestingConstants.SAML_ID_CONS.toString());
    spAuthData.setIssuer(TestingConstants.SAML_ISSUER_CONS.toString());
    
    final AUSPEPS auspeps = new AUSPEPS();
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    when(mockSession.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    when(mockSession.get(PEPSParameters.SAML_IN_RESPONSE_TO.toString()))
      .thenReturn(TestingConstants.SAML_ID_CONS.toString());
    when(mockSession.get(PEPSParameters.REMOTE_ADDR.toString())).thenReturn(
      TestingConstants.USER_IP_CONS.toString());
    when(mockSession.get(PEPSParameters.SP_URL.toString())).thenReturn(
      TestingConstants.ASSERTION_URL_CONS.toString());
    
    final ISPEPSSAMLService mockSamlService = mock(ISPEPSSAMLService.class);
    when(
      mockSamlService.getSAMLToken(mockParameters,
        PEPSErrors.COLLEAGUE_RESP_INVALID_SAML.name(), false)).thenReturn(
      SAML_TOKEN_ARRAY);
    
    authData.setPersonalAttributeList(ATTR_LIST);
    when(
      mockSamlService.processAuthenticationResponse((byte[]) any(),
        (STORKAuthnRequest) any(), (STORKAuthnRequest) any(), anyString()))
      .thenReturn(authData);
    when(
      mockSamlService.generateAuthenticationResponse((STORKAuthnRequest) any(),
        anyString())).thenReturn(SAML_NATIVE_TOKEN_ARRAY);
    
    auspeps.setSamlService(mockSamlService);
    
    final ISPEPSTranslatorService mockTransService =
      mock(ISPEPSTranslatorService.class);
    when(mockTransService.normaliseAttributeNamesToStork(ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auspeps.setTransService(mockTransService);
    
    spAuthData.setTokenSaml(NATIVE_ATTR_LIST.toString().getBytes());
    
    final STORKAuthnRequest authResp =
      auspeps.getAuthenticationResponse(mockParameters, mockSession);
    assertSame(spAuthData.getAssertionConsumerServiceURL(),
      authResp.getAssertionConsumerServiceURL());
    assertSame(spAuthData.getIssuer(), authResp.getIssuer());
    assertSame(spAuthData.getSamlId(), authResp.getSamlId());
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#sendRedirect(byte[])}. Testing null
   * value. Must throw {@link NullPointerException}.
   */
  @Test(expected = NullPointerException.class)
  public void testSendRedirectNullToken() {
    final AUSPEPS auspeps = new AUSPEPS();
    auspeps.sendRedirect(null);
  }
  
  /**
   * Test method for
   * {@link eu.stork.peps.auth.speps.AUSPEPS#sendRedirect(byte[])}. Must
   * succeed.
   */
  @Test
  public void testSendRedirect() {
    final AUSPEPS auspeps = new AUSPEPS();
    assertEquals("ARequestAAAAA/RequesestA",
      auspeps.sendRedirect(SAML_TOKEN_ARRAY));
  }
}
