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
package eu.stork.peps.auth.cpeps.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.Properties;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.stork.peps.auth.commons.CitizenConsent;
import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.exceptions.CPEPSException;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import eu.stork.peps.auth.cpeps.AUCPEPS;
import eu.stork.peps.auth.cpeps.ICPEPSCitizenService;
import eu.stork.peps.auth.cpeps.ICPEPSSAMLService;
import eu.stork.peps.auth.cpeps.ICPEPSTranslatorService;
import eu.stork.peps.auth.util.tests.TestingConstants;

/**
 * Functional testing class to {@link AUCPEPS}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUCPEPSTestCase {
  
  /**
   * Stork Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList STORK_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy derived attribute values.
   */
  private static IPersonalAttributeList DER_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Stork Personal Attribute List with dummy derived attribute values.
   */
  private static IPersonalAttributeList STORK_DER_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy stork attribute values.
   */
  private static IPersonalAttributeList NATIVE_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy stork attribute, no values.
   */
  private static IPersonalAttributeList NATIVE_ATTR_LIST_NO_DATA =
    new PersonalAttributeList();
  
  /**
   * Properties values for testing proposes.
   */
  private static Properties CONFIGS = new Properties();
  
  /**
   * Dummy User IP.
   */
  private static String USER_IP = "10.10.10.10";
  
  /**
   * Initialising class variables.
   * 
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void runBeforeClass() throws Exception {
    
    STORK_ATTR_LIST
      .populate("dateOfBirth:true:[2011-11-11,]:Available;age:false:[15,]:Available;");
    
    DER_ATTR_LIST
      .populate("DataNascimento:true:[11/11/2011,]:Available;isAgeOver:false:[15,]:Available;");
    
    STORK_DER_ATTR_LIST
      .populate("dateOfBirth:true:[11/11/2011,]:Available;isAgeOver:false:[15,]:Available;");
    
    NATIVE_ATTR_LIST
      .populate("DataNascimento:true:[11/11/2011,]:Available;Idade:false:[15,]:Available;");
    
    NATIVE_ATTR_LIST_NO_DATA
      .populate("DataNascimento:true:[,]:NotAvailable;Idade:false:[,]:NotAvailable;");
    
    CONFIGS.setProperty(PEPSErrors.CPEPS_REDIRECT_URL.errorCode(), "203006");
    CONFIGS.setProperty(PEPSErrors.CPEPS_REDIRECT_URL.errorMessage(),
      "invalid.cpeps.redirectUrl");
    
    CONFIGS.setProperty(PEPSErrors.AUTHENTICATION_FAILED_ERROR.errorCode(),
      "003002");
    CONFIGS.setProperty(PEPSErrors.AUTHENTICATION_FAILED_ERROR.errorMessage(),
      "authentication.failed");
    
    CONFIGS
      .setProperty(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorCode(), "203001");
    CONFIGS.setProperty(PEPSErrors.INVALID_ATTRIBUTE_LIST.errorMessage(),
      "invalid.attrlist");
    CONFIGS.setProperty(PEPSErrors.CPEPS_ATTR_NULL.errorCode(), "202005");
    CONFIGS.setProperty(PEPSErrors.CPEPS_ATTR_NULL.errorMessage(),
      "invalid.attrList.cpeps");
    
    PEPSUtil.createInstance(CONFIGS);
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#processAuthenticationRequest(Map, IStorkSession)}. Testing
   * an invalid saml token. Must throw {@link InvalidParameterPEPSException}.
   */
  @Test(expected = InvalidParameterPEPSException.class)
  public void testProcessAuthenticationRequestInvalidSaml() {
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenThrow(
      new InvalidParameterPEPSException(TestingConstants.ERROR_CODE_CONS
        .toString(), TestingConstants.ERROR_MESSAGE_CONS.toString()));
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUCPEPS aucpeps = new AUCPEPS();
    aucpeps.setSamlService(mockSamlService);
    aucpeps.processAuthenticationRequest(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#processAuthenticationRequest(Map, IStorkSession)}. Testing
   * an invalid saml token. Must throw {@link InvalidParameterPEPSException}.
   */
  @Test(expected = InvalidParameterPEPSException.class)
  public void testProcessAuthenticationRequestErrorValidatingSaml() {
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenReturn(new byte[0]);
    
    when(
      mockSamlService.processAuthenticationRequest((byte[]) any(),
        (IStorkSession) any(), anyString())).thenThrow(
      new InvalidParameterPEPSException(TestingConstants.ERROR_CODE_CONS
        .toString(), TestingConstants.ERROR_MESSAGE_CONS.toString()));
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUCPEPS aucpeps = new AUCPEPS();
    aucpeps.setSamlService(mockSamlService);
    aucpeps.processAuthenticationRequest(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#processAuthenticationRequest(Map, IStorkSession)}. Testing
   * an invalid qaa level. Must throw {@link CPEPSException}.
   */
  @Test(expected = CPEPSException.class)
  public void testProcessAuthenticationRequestInvalidQAA() {
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenReturn(new byte[0]);
    
    when(
      mockSamlService.processAuthenticationRequest((byte[]) any(),
        (IStorkSession) any(), anyString())).thenThrow(
      new CPEPSException(TestingConstants.SAML_TOKEN_CONS.toString(),
        TestingConstants.ERROR_CODE_CONS.toString(),
        TestingConstants.ERROR_MESSAGE_CONS.toString()));
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUCPEPS aucpeps = new AUCPEPS();
    aucpeps.setSamlService(mockSamlService);
    aucpeps.processAuthenticationRequest(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#processAuthenticationRequest(Map, IStorkSession)}. Must
   * succeed.
   */
  @Test
  public void testProcessAuthenticationRequest() {
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenReturn(new byte[0]);
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST_NO_DATA);
    
    when(
      mockSamlService.processAuthenticationRequest((byte[]) any(),
        (IStorkSession) any(), anyString())).thenReturn(authData);
    
    final ICPEPSTranslatorService mockTransService =
      mock(ICPEPSTranslatorService.class);
    when(mockTransService.normaliseAttributeNamesFromStork(STORK_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final ICPEPSCitizenService mockCitizenService =
      mock(ICPEPSCitizenService.class);
    when(
      mockCitizenService.updateAttributeList((IStorkSession) any(),
        (IPersonalAttributeList) any())).thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUCPEPS aucpeps = new AUCPEPS();
    aucpeps.setSamlService(mockSamlService);
    aucpeps.setTransService(mockTransService);
    aucpeps.setCitizenService(mockCitizenService);
    assertSame(authData,
      aucpeps.processAuthenticationRequest(mockParameters, mockSession));
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#processCitizenConsent(Map, IStorkSession, boolean)}. Must
   * succeed.
   */
  @Test
  public void testProcessCitizenConsentNoConsent() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(STORK_DER_ATTR_LIST);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    when(mockSession.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ICPEPSTranslatorService mockTransService =
      mock(ICPEPSTranslatorService.class);
    when(mockTransService.deriveAttributesFromStork(STORK_DER_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    aucpeps.setTransService(mockTransService);
    final Map<String, String> mockParameters = mock(Map.class);
    
    assertSame(NATIVE_ATTR_LIST_NO_DATA,
      aucpeps.processCitizenConsent(mockParameters, mockSession, false));
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#processCitizenConsent(Map, IStorkSession, boolean)}. Must
   * succeed.
   */
  @Test
  public void testProcessCitizenConsentWithConsent() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(STORK_DER_ATTR_LIST);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    when(mockSession.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ICPEPSTranslatorService mockTransService =
      mock(ICPEPSTranslatorService.class);
    when(mockTransService.deriveAttributesFromStork(STORK_DER_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final ICPEPSCitizenService mockCitizenService =
      mock(ICPEPSCitizenService.class);
    when(
      mockCitizenService.getCitizenConsent((Map<String, String>) any(),
        (IPersonalAttributeList) any())).thenReturn(new CitizenConsent());
    when(
      mockCitizenService.updateAttributeList((CitizenConsent) any(),
        (IPersonalAttributeList) any())).thenReturn(STORK_DER_ATTR_LIST);
    
    aucpeps.setCitizenService(mockCitizenService);
    aucpeps.setTransService(mockTransService);
    final Map<String, String> mockParameters = mock(Map.class);
    
    assertSame(NATIVE_ATTR_LIST_NO_DATA,
      aucpeps.processCitizenConsent(mockParameters, mockSession, true));
    
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#processCitizenConsent(Map, IStorkSession, boolean)}. Must
   * throw a {@link CPEPSException}.
   */
  @Test(expected = CPEPSException.class)
  public void testProcessCitizenConsentWithConsentEmptyAttrList() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(STORK_DER_ATTR_LIST);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    when(mockSession.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ICPEPSTranslatorService mockTransService =
      mock(ICPEPSTranslatorService.class);
    when(mockTransService.deriveAttributesFromStork(STORK_DER_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final ICPEPSCitizenService mockCitizenService =
      mock(ICPEPSCitizenService.class);
    when(
      mockCitizenService.getCitizenConsent((Map<String, String>) any(),
        (IPersonalAttributeList) any())).thenReturn(new CitizenConsent());
    when(
      mockCitizenService.updateAttributeList((CitizenConsent) any(),
        (IPersonalAttributeList) any()))
      .thenReturn(new PersonalAttributeList());
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    aucpeps.setSamlService(mockSamlService);
    aucpeps.setCitizenService(mockCitizenService);
    aucpeps.setTransService(mockTransService);
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    assertSame(NATIVE_ATTR_LIST_NO_DATA,
      aucpeps.processCitizenConsent(mockParameters, mockSession, true));
    
  }
  
  /**
   * Test method for {@link AUCPEPS#processIdPResponse(Map, IStorkSession)}.
   * Testing authentication failed. Must throw a {@link CPEPSException}.
   */
  @Test(expected = CPEPSException.class)
  public void testProcessIdPResponseAuthFailed() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final Map<String, String> mockParameters = mock(Map.class);
    when(mockParameters.get(PEPSParameters.ERROR_CODE.toString())).thenReturn(
      TestingConstants.ERROR_CODE_CONS.toString());
    when(mockParameters.get(PEPSParameters.ERROR_SUBCODE.toString()))
      .thenReturn(TestingConstants.SUB_ERROR_CODE_CONS.toString());
    when(mockParameters.get(PEPSParameters.REMOTE_ADDR.toString())).thenReturn(
      TestingConstants.USER_IP_CONS.toString());
    when(mockParameters.get(PEPSParameters.ERROR_CODE.toString())).thenReturn(
      TestingConstants.ERROR_CODE_CONS.toString());
    when(mockParameters.get(PEPSParameters.ERROR_CODE.toString())).thenReturn(
      TestingConstants.ERROR_CODE_CONS.toString());
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    aucpeps.setSamlService(mockSamlService);
    aucpeps.processIdPResponse(mockParameters, mockSession);
  }
  
  /**
   * Test method for {@link AUCPEPS#processIdPResponse(Map, IStorkSession)}.
   * Testing authentication failed. Must throw a {@link CPEPSException}.
   */
  @Test(expected = CPEPSException.class)
  public void testProcessIdPResponseInvalidAttrList() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    aucpeps.setSamlService(mockSamlService);
    aucpeps.processIdPResponse(mockParameters, mockSession);
  }
  
  /**
   * Test method for {@link AUCPEPS#processIdPResponse(Map, IStorkSession)}.
   * Must succeed.
   */
  @Test
  public void testProcessIdPResponse() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final Map<String, String> mockParameters = mock(Map.class);
    when(mockParameters.get(PEPSParameters.ATTRIBUTE_LIST.toString()))
      .thenReturn(NATIVE_ATTR_LIST.toString());
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    final ICPEPSCitizenService mockCitService =
      mock(ICPEPSCitizenService.class);
    when(
      mockCitService.updateAttributeListValues(mockSession, NATIVE_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    
    aucpeps.setSamlService(mockSamlService);
    aucpeps.setCitizenService(mockCitService);
    
    aucpeps.processIdPResponse(mockParameters, mockSession);
  }
  
  @Test(expected = CPEPSException.class)
  public void testProcessAPResponseNullStrAttrList() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final Map<String, String> mockParameters = mock(Map.class);
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    final IStorkSession mockSession = mock(IStorkSession.class);
    when(mockSession.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    aucpeps.setSamlService(mockSamlService);
    aucpeps.processAPResponse(mockParameters, mockSession);
  }
  
  @Test
  public void testProcessAPResponse() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final Map<String, String> mockParameters = mock(Map.class);
    when(mockParameters.get(PEPSParameters.ATTRIBUTE_LIST.toString()))
      .thenReturn(NATIVE_ATTR_LIST.toString());
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    when(mockSession.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ICPEPSCitizenService mockCitizenService =
      mock(ICPEPSCitizenService.class);
    when(
      mockCitizenService.updateAttributeListValues(mockSession,
        NATIVE_ATTR_LIST)).thenReturn(NATIVE_ATTR_LIST);
    when(mockCitizenService.updateAttributeList(mockSession, DER_ATTR_LIST))
      .thenReturn(DER_ATTR_LIST);
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    when(
      mockSamlService.generateAuthenticationResponse((STORKAuthnRequest) any(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    final ICPEPSTranslatorService mockTransService =
      mock(ICPEPSTranslatorService.class);
    when(
      mockTransService.deriveAttributesToStork((ICPEPSSAMLService) any(),
        (IStorkSession) any(), (STORKAuthnRequest) any(), anyString()))
      .thenReturn(DER_ATTR_LIST);
    when(mockTransService.normaliseAttributeNamesToStork(DER_ATTR_LIST))
      .thenReturn(STORK_DER_ATTR_LIST);
    when(
      mockTransService.normaliseAttributeValuesToStork(
        (ICPEPSSAMLService) any(), (STORKAuthnRequest) any(), anyString()))
      .thenReturn(STORK_ATTR_LIST);
    
    aucpeps.setSamlService(mockSamlService);
    aucpeps.setCitizenService(mockCitizenService);
    aucpeps.setTransService(mockTransService);
    assertNotNull(aucpeps.processAPResponse(mockParameters, mockSession)
      .getPersonalAttributeList());
  }
  
  /**
   * Test method for
   * {@link AUCPEPS#generateSamlTokenFail(STORKAuthnRequest, PEPSErrors, String)}
   * . Must succeed.
   */
  @Test
  public void testGenerateSamlTokenFail() {
    final AUCPEPS aucpeps = new AUCPEPS();
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    aucpeps.setSamlService(mockSamlService);
    assertEquals("", aucpeps.generateSamlTokenFail(authData,
      PEPSErrors.AUTHENTICATION_FAILED_ERROR, USER_IP));
  }
  
}
