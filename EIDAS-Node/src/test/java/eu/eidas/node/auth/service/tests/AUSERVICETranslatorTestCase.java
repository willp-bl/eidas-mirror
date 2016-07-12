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

import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.auth.specific.ITranslatorService;
import eu.eidas.node.auth.service.AUSERVICETranslator;
import eu.eidas.node.auth.service.ISERVICESAMLService;

/**
 * Functional testing class to {@link AUSERVICETranslator}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUSERVICETranslatorTestCase {
  
  /**
   * Properties values for testing proposes.
   */
  private static Properties CONFIGS = new Properties();
  
  /**
   * Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList EIDAS_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy derived attribute values.
   */
  private static IPersonalAttributeList EIDAS_DER_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy native attribute values.
   */
  private static IPersonalAttributeList NATIVE_ATTR_LIST_VALUES =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList NATIVE_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Invalid Personal Attribute List.
   */
  private static IPersonalAttributeList INV_ATTR_LIST =
    new PersonalAttributeList();
  
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
      .populate("dateOfBirth:true:[2011-11-11,]:NotAvailable;age:false:[15,]:Available;");
    EIDAS_DER_ATTR_LIST
      .populate("dateOfBirth:true:[2011-11-11,]:NotAvailable;isAgeOver:false:[15,]:Available;");
    NATIVE_ATTR_LIST
      .populate("DataNascimento:true:[2011-11-11,]:NotAvailable;Idade:false:[15,]:Available;");
    NATIVE_ATTR_LIST_VALUES
      .populate("DataNascimento:true:[11/11/2011,]:NotAvailable;Idade:false:[15,]:Available;");
    
    CONFIGS.setProperty(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorCode(),
      "203001");
    CONFIGS.setProperty(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorMessage(),
      "invalid.attr.value");
    
    EIDASUtil.createInstance(CONFIGS);
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#normaliseAttributeNamesToFormat(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesToFormat() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesTo(NATIVE_ATTR_LIST))
      .thenReturn(EIDAS_ATTR_LIST);
    
    auserviceTrans.setSpecificNode(mockSpecific);
    assertSame(EIDAS_ATTR_LIST,
      auserviceTrans.normaliseAttributeNamesToFormat(NATIVE_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#normaliseAttributeNamesToFormat(IPersonalAttributeList)}
   * . Testing an invalid personal attribute list and must throw an
   * {@link InvalidParameterEIDASException}.
   */
  @Test(expected = InvalidParameterEIDASException.class)
  public void testNormaliseAttributeNamesToFormatInvalid() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesTo(INV_ATTR_LIST)).thenThrow(
      new InvalidParameterEIDASException("ERROR_CODE", "ERROR_MESSAGE"));
    auserviceTrans.setSpecificNode(mockSpecific);
    auserviceTrans.normaliseAttributeNamesToFormat(INV_ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#normaliseAttributeValuesToFormat(ISERVICESAMLService, EIDASAuthnRequest, String)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeValuesToFormat() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeValuesTo(NATIVE_ATTR_LIST_VALUES))
      .thenReturn(EIDAS_ATTR_LIST);
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST_VALUES);
    
    auserviceTrans.setSpecificNode(mockSpecific);
    assertSame(EIDAS_ATTR_LIST, auserviceTrans.normaliseAttributeValuesToFormat(
      mockSamlService, authData, USER_IP));
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#normaliseAttributeValuesToFormat(ISERVICESAMLService, EIDASAuthnRequest, String)}
   * . Testing an invalid personal attribute list and must throw a
   * {@link EIDASServiceException}.
   */
  @Test(expected = EIDASServiceException.class)
  public void testNormaliseAttributeValuesToFormatInvalid() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeValuesTo(NATIVE_ATTR_LIST))
      .thenThrow(new SecurityEIDASException("ERROR_CODE", "ERROR_MESSAGE"));
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    auserviceTrans.setSpecificNode(mockSpecific);
    assertSame(NATIVE_ATTR_LIST_VALUES,
      auserviceTrans.normaliseAttributeValuesToFormat(mockSamlService, authData,
        USER_IP));
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#normaliseAttributeNamesFromFormat(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesFromFormat() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesFrom(EIDAS_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auserviceTrans.setSpecificNode(mockSpecific);
    assertSame(NATIVE_ATTR_LIST,
      auserviceTrans.normaliseAttributeNamesFromFormat(EIDAS_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#normaliseAttributeNamesFromFormat(IPersonalAttributeList)}
   * . Testing an invalid personal attribute list and must throw a
   * {@link InvalidParameterEIDASException}.
   */
  @Test(expected = InvalidParameterEIDASException.class)
  public void testNormaliseAttributeNamesFromFormatInvalid() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesFrom(INV_ATTR_LIST))
      .thenThrow(
        new InvalidParameterEIDASException("ERROR_CODE", "ERROR_MESSAGE"));
    auserviceTrans.setSpecificNode(mockSpecific);
    auserviceTrans.normaliseAttributeNamesFromFormat(INV_ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#deriveAttributesToFormat(ISERVICESAMLService, IEIDASSession, EIDASAuthnRequest, String)}
   * . Must Succeed.
   */
  @Test
  public void testDeriveAttributesToFormat() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.deriveAttributeTo(mockSession, NATIVE_ATTR_LIST))
      .thenReturn(EIDAS_DER_ATTR_LIST);
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    auserviceTrans.setSpecificNode(mockSpecific);
    assertSame(EIDAS_DER_ATTR_LIST, auserviceTrans.deriveAttributesToFormat(
      mockSamlService, mockSession, authData, USER_IP));
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#deriveAttributesToFormat(ISERVICESAMLService, IEIDASSession, EIDASAuthnRequest, String)}
   * . Testing an invalid personal attribute list and must throw a
   * {@link EIDASServiceException}.
   */
  @Test(expected = EIDASServiceException.class)
  public void testDeriveAttributesToFormatInvalid() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    
    final ISERVICESAMLService mockSamlService = mock(ISERVICESAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    final IEIDASSession mockSession = mock(IEIDASSession.class);
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(INV_ATTR_LIST);
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.deriveAttributeTo(mockSession, INV_ATTR_LIST))
      .thenThrow(new SecurityEIDASException("ERROR_CODE", "ERROR_MESSAGE"));
    
    auserviceTrans.setSpecificNode(mockSpecific);
    
    auserviceTrans.deriveAttributesToFormat(mockSamlService, mockSession,
      authData, USER_IP);
  }
  
  /**
   * Test method for
   * {@link AUSERVICETranslator#deriveAttributesFromFormat(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testDeriveAttributesFromFormat() {
    final AUSERVICETranslator auserviceTrans = new AUSERVICETranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.deriveAttributeFrom(NATIVE_ATTR_LIST)).thenReturn(
      EIDAS_DER_ATTR_LIST);
    
    auserviceTrans.setSpecificNode(mockSpecific);
    assertSame(EIDAS_DER_ATTR_LIST,
      auserviceTrans.deriveAttributesFromFormat(NATIVE_ATTR_LIST));
  }
}
