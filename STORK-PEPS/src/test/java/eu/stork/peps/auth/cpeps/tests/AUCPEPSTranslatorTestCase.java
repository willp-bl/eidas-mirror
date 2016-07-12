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

import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.exceptions.CPEPSException;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import eu.stork.peps.auth.commons.exceptions.SecurityPEPSException;
import eu.stork.peps.auth.cpeps.AUCPEPSTranslator;
import eu.stork.peps.auth.cpeps.ICPEPSSAMLService;
import eu.stork.peps.auth.specific.ITranslatorService;

/**
 * Functional testing class to {@link AUCPEPSTranslator}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUCPEPSTranslatorTestCase {
  
  /**
   * Properties values for testing proposes.
   */
  private static Properties CONFIGS = new Properties();
  
  /**
   * Stork Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList STORK_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Stork Personal Attribute List with dummy derived attribute values.
   */
  private static IPersonalAttributeList STORK_DER_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy native attribute values.
   */
  private static IPersonalAttributeList NATIVE_ATTR_LIST_VALUES =
    new PersonalAttributeList();
  
  /**
   * Native Personal Attribute List with dummy stork attribute values.
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
    STORK_ATTR_LIST
      .populate("dateOfBirth:true:[2011-11-11,]:NotAvailable;age:false:[15,]:Available;");
    STORK_DER_ATTR_LIST
      .populate("dateOfBirth:true:[2011-11-11,]:NotAvailable;isAgeOver:false:[15,]:Available;");
    NATIVE_ATTR_LIST
      .populate("DataNascimento:true:[2011-11-11,]:NotAvailable;Idade:false:[15,]:Available;");
    NATIVE_ATTR_LIST_VALUES
      .populate("DataNascimento:true:[11/11/2011,]:NotAvailable;Idade:false:[15,]:Available;");
    
    CONFIGS.setProperty(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorCode(),
      "203001");
    CONFIGS.setProperty(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorMessage(),
      "invalid.attr.value");
    
    PEPSUtil.createInstance(CONFIGS);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#normaliseAttributeNamesToStork(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesToStork() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesToStork(NATIVE_ATTR_LIST))
      .thenReturn(STORK_ATTR_LIST);
    
    aucpepsTrans.setSpecificPeps(mockSpecific);
    assertSame(STORK_ATTR_LIST,
      aucpepsTrans.normaliseAttributeNamesToStork(NATIVE_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#normaliseAttributeNamesToStork(IPersonalAttributeList)}
   * . Testing an invalid personal attribute list and must throw an
   * {@link InvalidParameterPEPSException}.
   */
  @Test(expected = InvalidParameterPEPSException.class)
  public void testNormaliseAttributeNamesToStorkInvalid() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesToStork(INV_ATTR_LIST)).thenThrow(
      new InvalidParameterPEPSException("ERROR_CODE", "ERROR_MESSAGE"));
    aucpepsTrans.setSpecificPeps(mockSpecific);
    aucpepsTrans.normaliseAttributeNamesToStork(INV_ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#normaliseAttributeValuesToStork(ICPEPSSAMLService, STORKAuthnRequest, String)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeValuesToStork() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeValuesToStork(NATIVE_ATTR_LIST_VALUES))
      .thenReturn(STORK_ATTR_LIST);
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST_VALUES);
    
    aucpepsTrans.setSpecificPeps(mockSpecific);
    assertSame(STORK_ATTR_LIST, aucpepsTrans.normaliseAttributeValuesToStork(
      mockSamlService, authData, USER_IP));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#normaliseAttributeValuesToStork(ICPEPSSAMLService, STORKAuthnRequest, String)}
   * . Testing an invalid personal attribute list and must throw a
   * {@link CPEPSException}.
   */
  @Test(expected = CPEPSException.class)
  public void testNormaliseAttributeValuesToStorkInvalid() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeValuesToStork(NATIVE_ATTR_LIST))
      .thenThrow(new SecurityPEPSException("ERROR_CODE", "ERROR_MESSAGE"));
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    aucpepsTrans.setSpecificPeps(mockSpecific);
    assertSame(NATIVE_ATTR_LIST_VALUES,
      aucpepsTrans.normaliseAttributeValuesToStork(mockSamlService, authData,
        USER_IP));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#normaliseAttributeNamesFromStork(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesFromStork() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesFromStork(STORK_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    aucpepsTrans.setSpecificPeps(mockSpecific);
    assertSame(NATIVE_ATTR_LIST,
      aucpepsTrans.normaliseAttributeNamesFromStork(STORK_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#normaliseAttributeNamesFromStork(IPersonalAttributeList)}
   * . Testing an invalid personal attribute list and must throw a
   * {@link InvalidParameterPEPSException}.
   */
  @Test(expected = InvalidParameterPEPSException.class)
  public void testNormaliseAttributeNamesFromStorkInvalid() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesFromStork(INV_ATTR_LIST))
      .thenThrow(
        new InvalidParameterPEPSException("ERROR_CODE", "ERROR_MESSAGE"));
    aucpepsTrans.setSpecificPeps(mockSpecific);
    aucpepsTrans.normaliseAttributeNamesFromStork(INV_ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#deriveAttributesToStork(ICPEPSSAMLService, IStorkSession, STORKAuthnRequest, String)}
   * . Must Succeed.
   */
  @Test
  public void testDeriveAttributesToStork() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.deriveAttributeToStork(mockSession, NATIVE_ATTR_LIST))
      .thenReturn(STORK_DER_ATTR_LIST);
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(NATIVE_ATTR_LIST);
    
    aucpepsTrans.setSpecificPeps(mockSpecific);
    assertSame(STORK_DER_ATTR_LIST, aucpepsTrans.deriveAttributesToStork(
      mockSamlService, mockSession, authData, USER_IP));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#deriveAttributesToStork(ICPEPSSAMLService, IStorkSession, STORKAuthnRequest, String)}
   * . Testing an invalid personal attribute list and must throw a
   * {@link CPEPSException}.
   */
  @Test(expected = CPEPSException.class)
  public void testDeriveAttributesToStorkInvalid() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    
    final ICPEPSSAMLService mockSamlService = mock(ICPEPSSAMLService.class);
    when(
      mockSamlService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    final IStorkSession mockSession = mock(IStorkSession.class);
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(INV_ATTR_LIST);
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.deriveAttributeToStork(mockSession, INV_ATTR_LIST))
      .thenThrow(new SecurityPEPSException("ERROR_CODE", "ERROR_MESSAGE"));
    
    aucpepsTrans.setSpecificPeps(mockSpecific);
    
    aucpepsTrans.deriveAttributesToStork(mockSamlService, mockSession,
      authData, USER_IP);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSTranslator#deriveAttributesFromStork(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testDeriveAttributesFromStork() {
    final AUCPEPSTranslator aucpepsTrans = new AUCPEPSTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.deriveAttributeFromStork(NATIVE_ATTR_LIST)).thenReturn(
      STORK_DER_ATTR_LIST);
    
    aucpepsTrans.setSpecificPeps(mockSpecific);
    assertSame(STORK_DER_ATTR_LIST,
      aucpepsTrans.deriveAttributesFromStork(NATIVE_ATTR_LIST));
  }
}
