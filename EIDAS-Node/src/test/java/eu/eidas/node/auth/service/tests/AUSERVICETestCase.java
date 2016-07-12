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
package eu.eidas.node.auth.service.tests;

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

import eu.eidas.auth.commons.CitizenConsent;
import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.node.auth.service.AUSERVICE;
import eu.eidas.node.auth.service.ISERVICECitizenService;
import eu.eidas.node.auth.service.ISERVICESAMLService;
import eu.eidas.node.auth.service.ISERVICETranslatorService;
import eu.eidas.node.auth.util.tests.TestingConstants;

/**
 * Functional testing class to {@link AUSERVICE}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUSERVICETestCase {
  
  /**
   * Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList EIDAS_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy derived attribute values.
   */
  private static IPersonalAttributeList DER_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy derived attribute values.
   */
  private static IPersonalAttributeList EIDAS_DER_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList NATIVE_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy attribute, no values.
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
    
    EIDAS_ATTR_LIST
      .populate("dateOfBirth:true:[2011-11-11,]:Available;age:false:[15,]:Available;");
    
    DER_ATTR_LIST
      .populate("DataNascimento:true:[11/11/2011,]:Available;isAgeOver:false:[15,]:Available;");
    
    EIDAS_DER_ATTR_LIST
      .populate("dateOfBirth:true:[11/11/2011,]:Available;isAgeOver:false:[15,]:Available;");
    
    NATIVE_ATTR_LIST
      .populate("DataNascimento:true:[11/11/2011,]:Available;Idade:false:[15,]:Available;");
    
    NATIVE_ATTR_LIST_NO_DATA
      .populate("DataNascimento:true:[,]:NotAvailable;Idade:false:[,]:NotAvailable;");
    
    CONFIGS.setProperty(EIDASErrors.SERVICE_REDIRECT_URL.errorCode(), "203006");
    CONFIGS.setProperty(EIDASErrors.SERVICE_REDIRECT_URL.errorMessage(),
      "invalid.service.redirectUrl");
    
    CONFIGS.setProperty(EIDASErrors.AUTHENTICATION_FAILED_ERROR.errorCode(),
      "003002");
    CONFIGS.setProperty(EIDASErrors.AUTHENTICATION_FAILED_ERROR.errorMessage(),
      "authentication.failed");
    
    CONFIGS
      .setProperty(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorCode(), "203001");
    CONFIGS.setProperty(EIDASErrors.INVALID_ATTRIBUTE_LIST.errorMessage(),
      "invalid.attrlist");
    CONFIGS.setProperty(EIDASErrors.SERVICE_ATTR_NULL.errorCode(), "202005");
    CONFIGS.setProperty(EIDASErrors.SERVICE_ATTR_NULL.errorMessage(),
      "invalid.attrList.service");
    
    EIDASUtil.createInstance(CONFIGS);
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#processAuthenticationRequest(Map, IEIDASSession)}. Testing
   * an invalid saml token. Must throw {@link InvalidParameterEIDASException}.
   */
  @Test(expected = InvalidParameterEIDASException.class)
  public void testProcessAuthenticationRequestInvalidSaml() {
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenThrow(
      new InvalidParameterEIDASException(TestingConstants.ERROR_CODE_CONS
        .toString(), TestingConstants.ERROR_MESSAGE_CONS.toString()));
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUSERVICE auservice = new AUSERVICE();
    auservice.setSamlService(mockSamlService);
    auservice.processAuthenticationRequest(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#processAuthenticationRequest(Map, IEIDASSession)}. Testing
   * an invalid saml token. Must throw {@link InvalidParameterEIDASException}.
   */
  @Test(expected = InvalidParameterEIDASException.class)
  public void testProcessAuthenticationRequestErrorValidatingSaml() {
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenReturn(new byte[0]);
    
    when(
      mockSamlService.processAuthenticationRequest((byte[]) any(),
        (IEIDASSession) any(), anyString())).thenThrow(
      new InvalidParameterEIDASException(TestingConstants.ERROR_CODE_CONS
        .toString(), TestingConstants.ERROR_MESSAGE_CONS.toString()));
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUSERVICE auservice = new AUSERVICE();
    auservice.setSamlService(mockSamlService);
    auservice.processAuthenticationRequest(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#processAuthenticationRequest(Map, IEIDASSession)}. Testing
   * an invalid qaa level. Must throw {@link EIDASServiceException}.
   */
  @Test(expected = EIDASServiceException.class)
  public void testProcessAuthenticationRequestInvalidQAA() {
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenReturn(new byte[0]);
    
    when(
      mockSamlService.processAuthenticationRequest((byte[]) any(),
        (IEIDASSession) any(), anyString())).thenThrow(
      new EIDASServiceException(TestingConstants.SAML_TOKEN_CONS.toString(),
        TestingConstants.ERROR_CODE_CONS.toString(),
        TestingConstants.ERROR_MESSAGE_CONS.toString()));
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUSERVICE auservice = new AUSERVICE();
    auservice.setSamlService(mockSamlService);
    auservice.processAuthenticationRequest(mockParameters, mockSession);
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#processAuthenticationRequest(Map, IEIDASSession)}. Must
   * succeed.
   */
  @Test
  public void testProcessAuthenticationRequest() {
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(mockSamlService.getSAMLToken(anyString())).thenReturn(new byte[0]);
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST_NO_DATA);
    
    when(
      mockSamlService.processAuthenticationRequest((byte[]) any(),
        (IEIDASSession) any(), anyString())).thenReturn(authData);
    
    final ISERVICETranslatorService mockTransService =
      mock(ISERVICETranslatorService.class);
    when(mockTransService.normaliseAttributeNamesFromFormat(EIDAS_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final ISERVICECitizenService mockCitizenService =
      mock(ISERVICECitizenService.class);
    when(
      mockCitizenService.updateAttributeList((IEIDASSession) any(),
        (IPersonalAttributeList) any())).thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    final Map<String, String> mockParameters = mock(Map.class);
    final AUSERVICE auservice = new AUSERVICE();
    auservice.setSamlService(mockSamlService);
    auservice.setTransService(mockTransService);
    auservice.setCitizenService(mockCitizenService);
    assertSame(authData,
      auservice.processAuthenticationRequest(mockParameters, mockSession));
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#processCitizenConsent(Map, IEIDASSession, boolean)}. Must
   * succeed.
   */
  @Test
  public void testProcessCitizenConsentNoConsent() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(EIDAS_DER_ATTR_LIST);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    when(mockSession.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ISERVICETranslatorService mockTransService =
      mock(ISERVICETranslatorService.class);
    when(mockTransService.deriveAttributesFromFormat(EIDAS_DER_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    auservice.setTransService(mockTransService);
    final Map<String, String> mockParameters = mock(Map.class);
    
    assertSame(NATIVE_ATTR_LIST_NO_DATA,
      auservice.processCitizenConsent(mockParameters, mockSession, false));
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#processCitizenConsent(Map, IEIDASSession, boolean)}. Must
   * succeed.
   */
  @Test
  public void testProcessCitizenConsentWithConsent() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(EIDAS_DER_ATTR_LIST);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    when(mockSession.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ISERVICETranslatorService mockTransService =
      mock(ISERVICETranslatorService.class);
    when(mockTransService.deriveAttributesFromFormat(EIDAS_DER_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final ISERVICECitizenService mockCitizenService =
      mock(ISERVICECitizenService.class);
    when(
      mockCitizenService.getCitizenConsent((Map<String, String>) any(),
        (IPersonalAttributeList) any())).thenReturn(new CitizenConsent());
    when(
      mockCitizenService.updateAttributeList((CitizenConsent) any(),
        (IPersonalAttributeList) any())).thenReturn(EIDAS_DER_ATTR_LIST);
    
    auservice.setCitizenService(mockCitizenService);
    auservice.setTransService(mockTransService);
    final Map<String, String> mockParameters = mock(Map.class);
    
    assertSame(NATIVE_ATTR_LIST_NO_DATA,
      auservice.processCitizenConsent(mockParameters, mockSession, true));
    
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#processCitizenConsent(Map, IEIDASSession, boolean)}. Must
   * throw a {@link EIDASServiceException}.
   */
  @Test(expected = EIDASServiceException.class)
  public void testProcessCitizenConsentWithConsentEmptyAttrList() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(EIDAS_DER_ATTR_LIST);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    when(mockSession.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ISERVICETranslatorService mockTransService =
      mock(ISERVICETranslatorService.class);
    when(mockTransService.deriveAttributesFromFormat(EIDAS_DER_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST_NO_DATA);
    
    final ISERVICECitizenService mockCitizenService =
      mock(ISERVICECitizenService.class);
    when(
      mockCitizenService.getCitizenConsent((Map<String, String>) any(),
        (IPersonalAttributeList) any())).thenReturn(new CitizenConsent());
    when(
      mockCitizenService.updateAttributeList((CitizenConsent) any(),
        (IPersonalAttributeList) any()))
      .thenReturn(new PersonalAttributeList());
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    auservice.setSamlService(mockSamlService);
    auservice.setCitizenService(mockCitizenService);
    auservice.setTransService(mockTransService);
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    assertSame(NATIVE_ATTR_LIST_NO_DATA,
      auservice.processCitizenConsent(mockParameters, mockSession, true));
    
  }
  
  /**
   * Test method for {@link AUSERVICE#processIdPResponse(Map, IEIDASSession)}.
   * Testing authentication failed. Must throw a {@link EIDASServiceException}.
   */
  @Test(expected = EIDASServiceException.class)
  public void testProcessIdPResponseAuthFailed() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final Map<String, String> mockParameters = mock(Map.class);
    when(mockParameters.get(EIDASParameters.ERROR_CODE.toString())).thenReturn(
      TestingConstants.ERROR_CODE_CONS.toString());
    when(mockParameters.get(EIDASParameters.ERROR_SUBCODE.toString()))
      .thenReturn(TestingConstants.SUB_ERROR_CODE_CONS.toString());
    when(mockParameters.get(EIDASParameters.REMOTE_ADDR.toString())).thenReturn(
      TestingConstants.USER_IP_CONS.toString());
    when(mockParameters.get(EIDASParameters.ERROR_CODE.toString())).thenReturn(
      TestingConstants.ERROR_CODE_CONS.toString());
    when(mockParameters.get(EIDASParameters.ERROR_CODE.toString())).thenReturn(
      TestingConstants.ERROR_CODE_CONS.toString());
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    auservice.setSamlService(mockSamlService);
    auservice.processIdPResponse(mockParameters, mockSession);
  }
  
  /**
   * Test method for {@link AUSERVICE#processIdPResponse(Map, IEIDASSession)}.
   * Testing authentication failed. Must throw a {@link EIDASServiceException}.
   */
  @Test(expected = EIDASServiceException.class)
  public void testProcessIdPResponseInvalidAttrList() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final Map<String, String> mockParameters = mock(Map.class);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    auservice.setSamlService(mockSamlService);
    auservice.processIdPResponse(mockParameters, mockSession);
  }
  
  /**
   * Test method for {@link AUSERVICE#processIdPResponse(Map, IEIDASSession)}.
   * Must succeed.
   */
  @Test
  public void testProcessIdPResponse() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final Map<String, String> mockParameters = mock(Map.class);
    when(mockParameters.get(EIDASParameters.ATTRIBUTE_LIST.toString()))
      .thenReturn(NATIVE_ATTR_LIST.toString());
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    final ISERVICECitizenService mockCitService =
      mock(ISERVICECitizenService.class);
    when(
      mockCitService.updateAttributeListValues(mockSession, NATIVE_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    
    auservice.setSamlService(mockSamlService);
    auservice.setCitizenService(mockCitService);
    
    auservice.processIdPResponse(mockParameters, mockSession);
  }
  
  @Test(expected = EIDASServiceException.class)
  public void testProcessAPResponseNullStrAttrList() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final Map<String, String> mockParameters = mock(Map.class);
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    when(mockSession.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    auservice.setSamlService(mockSamlService);
    auservice.processAPResponse(mockParameters, mockSession);
  }
  
  @Test
  public void testProcessAPResponse() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final Map<String, String> mockParameters = mock(Map.class);
    when(mockParameters.get(EIDASParameters.ATTRIBUTE_LIST.toString()))
      .thenReturn(NATIVE_ATTR_LIST.toString());
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    when(mockSession.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      authData);
    
    final ISERVICECitizenService mockCitizenService =
      mock(ISERVICECitizenService.class);
    when(
      mockCitizenService.updateAttributeListValues(mockSession,
        NATIVE_ATTR_LIST)).thenReturn(NATIVE_ATTR_LIST);
    when(mockCitizenService.updateAttributeList(mockSession, DER_ATTR_LIST))
      .thenReturn(DER_ATTR_LIST);
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    when(
      mockSamlService.generateAuthenticationResponse((EIDASAuthnRequest) any(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    final ISERVICETranslatorService mockTransService =
      mock(ISERVICETranslatorService.class);
    when(
      mockTransService.deriveAttributesToFormat((ISERVICESAMLService) any(),
        (IEIDASSession) any(), (EIDASAuthnRequest) any(), anyString()))
      .thenReturn(DER_ATTR_LIST);
    when(mockTransService.normaliseAttributeNamesToFormat(DER_ATTR_LIST))
      .thenReturn(EIDAS_DER_ATTR_LIST);
    when(
      mockTransService.normaliseAttributeValuesToFormat(
        (ISERVICESAMLService) any(), (EIDASAuthnRequest) any(), anyString()))
      .thenReturn(EIDAS_ATTR_LIST);
    
    auservice.setSamlService(mockSamlService);
    auservice.setCitizenService(mockCitizenService);
    auservice.setTransService(mockTransService);
    assertNotNull(auservice.processAPResponse(mockParameters, mockSession)
      .getPersonalAttributeList());
  }
  
  /**
   * Test method for
   * {@link AUSERVICE#generateSamlTokenFail(EIDASAuthnRequest, EIDASErrors, String)}
   * . Must succeed.
   */
  @Test
  public void testGenerateSamlTokenFail() {
    final AUSERVICE auservice = new AUSERVICE();
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    auservice.setSamlService(mockSamlService);
    assertEquals("", auservice.generateSamlTokenFail(authData,
      EIDASErrors.AUTHENTICATION_FAILED_ERROR, USER_IP));
  }
  
}
