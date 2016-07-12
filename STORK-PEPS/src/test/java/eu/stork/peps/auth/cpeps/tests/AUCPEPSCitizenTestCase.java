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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
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
import eu.stork.peps.auth.cpeps.AUCPEPSCitizen;
import eu.stork.peps.auth.cpeps.ICPEPSCitizenService;
import eu.stork.peps.auth.cpeps.ICPEPSSAMLService;
import org.junit.runners.MethodSorters;

/**
 * Functional testing class to {@link AUCPEPSCitizen}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
@FixMethodOrder(MethodSorters.JVM)
public final class AUCPEPSCitizenTestCase {
  
  /**
   * Citizen Consent Object
   */
  private static ICPEPSCitizenService AUCPEPSCITIZEN = new AUCPEPSCitizen();
  
  /**
   * Empty String[].
   */
  private static String[] EMPTY_STR_ARRAY = new String[0];
  
  /**
   * Empty parameters.
   */
  private static Map<String, String> EMPTY_PARAMETERS =
    new HashMap<String, String>();
  
  /**
   * Parameters with dummy values.
   */
  private static Map<String, String> PARAMETERS = new HashMap<String, String>();
  
  /**
   * Empty Personal Attribute List.
   */
  private static IPersonalAttributeList EMPTY_ATTR_LIST =
    new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy attributes.
   */
  private static IPersonalAttributeList ATTR_LIST = new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy attributes but no values.
   */
  private static IPersonalAttributeList ATTR_LIST_NO_VALUES =
    new PersonalAttributeList();
  
  /**
   * Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList ATTR_LIST_VALUES =
    new PersonalAttributeList();
  
  /**
   * Empty STORKAuthnRequest object.
   */
  private static STORKAuthnRequest EMPTY_AUTH_DATA = new STORKAuthnRequest();
  
  /**
   * STORKAuthnRequest object.
   */
  private static STORKAuthnRequest AUTH_DATA = new STORKAuthnRequest();
  
  /**
   * STORKAuthnRequest object with no attribute values.
   */
  private static STORKAuthnRequest AUTH_DATA_NO_VALUES =
    new STORKAuthnRequest();
  
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
    ATTR_LIST.populate("isAgeOver:true:[15,]:Available;age:false:[,]:;");
    ATTR_LIST_NO_VALUES
      .populate("isAgeOver:true:[15,]:Available;age:false:[,]:;");
    ATTR_LIST_VALUES
      .populate("isAgeOver:true:[15,]:Available;age:false:[15,]:Available;");
    PARAMETERS.put("isAgeOver", "");
    PARAMETERS.put("age", "");
    AUTH_DATA.setPersonalAttributeList(ATTR_LIST);
    AUTH_DATA_NO_VALUES.setPersonalAttributeList(ATTR_LIST_NO_VALUES);
  }

  private STORKAuthnRequest getFreshRequestWithAttrs(){
    STORKAuthnRequest request=new STORKAuthnRequest();
    request.setPersonalAttributeList(ATTR_LIST);
    return request;
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#getCitizenConsent(Map, IPersonalAttributeList)}.
   * Using an empty parameters.
   */
  @Test
  public void testGetCitizenConsentEmptyParameters() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(EMPTY_PARAMETERS, ATTR_LIST);
    assertArrayEquals(consent.getMandatoryList().toArray(), EMPTY_STR_ARRAY);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#getCitizenConsent(Map, IPersonalAttributeList)}.
   * Using and empty personal attribute list.
   */
  @Test
  public void testGetCitizenConsentEmptyAttrList() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(PARAMETERS, EMPTY_ATTR_LIST);
    assertArrayEquals(consent.getMandatoryList().toArray(), EMPTY_STR_ARRAY);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#getCitizenConsent(Map, IPersonalAttributeList)} .
   */
  @Test
  public void testGetCitizenConsent() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    assertArrayEquals(consent.getMandatoryList().toArray(),
      new String[] { "isAgeOver" });
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#processCitizenConsent(CitizenConsent, STORKAuthnRequest, String, ICPEPSSAMLService)}
   * . Testing empty STORKAuthRequest and no exception should be thrown.
   */
  @Test
  public void testProcessCitizenConsentEmptyAuthData() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    
    final ICPEPSSAMLService mockedCpepsSAMLService =
      mock(ICPEPSSAMLService.class);
    
    when(
      mockedCpepsSAMLService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUCPEPSCITIZEN.processCitizenConsent(consent, EMPTY_AUTH_DATA, USER_IP,
      mockedCpepsSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#processCitizenConsent(CitizenConsent, STORKAuthnRequest, String, ICPEPSSAMLService)}
   * . Testing empty Consent and no exception should be thrown.
   */
  @Test
  public void testProcessCitizenConsentEmptyConsent() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    
    final ICPEPSSAMLService mockedCpepsSAMLService =
      mock(ICPEPSSAMLService.class);
    
    when(
      mockedCpepsSAMLService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUCPEPSCITIZEN.processCitizenConsent(consent, EMPTY_AUTH_DATA, USER_IP,
      mockedCpepsSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#processCitizenConsent(CitizenConsent, STORKAuthnRequest, String, ICPEPSSAMLService)}
   * . No exception should be thrown.
   */
  @Test
  public void testProcessCitizenConsent() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    
    final ICPEPSSAMLService mockedCpepsSAMLService =
      mock(ICPEPSSAMLService.class);
    
    when(
      mockedCpepsSAMLService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUCPEPSCITIZEN.processCitizenConsent(consent, EMPTY_AUTH_DATA, USER_IP,
      mockedCpepsSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#processCitizenConsent(CitizenConsent, STORKAuthnRequest, String, ICPEPSSAMLService)}
   * . An CPEPSException must be thrown.
   */
  @Test(expected = CPEPSException.class)
  public void testProcessCitizenConsentWrongConsent() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    final Properties configs = new Properties();
    configs.put(PEPSErrors.CITIZEN_RESPONSE_MANDATORY.errorCode(), "202007");
    configs.put(PEPSErrors.CITIZEN_RESPONSE_MANDATORY.errorMessage(),
      "no.consent.mand.attr");
    PEPSUtil.createInstance(configs);
    
    final ICPEPSSAMLService mockedCpepsSAMLService =
      mock(ICPEPSSAMLService.class);
    
    when(
      mockedCpepsSAMLService.generateErrorAuthenticationResponse(
        (STORKAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUCPEPSCITIZEN.processCitizenConsent(consent, AUTH_DATA, USER_IP,
      mockedCpepsSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . Testing and empty Consent type and a personal attribute list must be
   * returned.
   */
  @Test
  public void testUpdateAttributeListEmptyConsent() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUCPEPSCITIZEN.updateAttributeList(consent, ATTR_LIST);
    assertEquals(attrListConsent.toString(), "isAgeOver:true:[15,]:Available;");
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . Testing an empty attribute list and an empty attribute list must be
   * returned.
   */
  @Test
  public void testUpdateAttributeListEmptyAttrList() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUCPEPSCITIZEN.updateAttributeList(consent, EMPTY_ATTR_LIST);
    assertEquals(attrListConsent.toString(), "");
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . Testing an empty attribute list and a empty consent type: an empty
   * personal attribute list must be returned.
   */
  @Test
  public void testUpdateAttributeListEmpty() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUCPEPSCITIZEN.updateAttributeList(consent, EMPTY_ATTR_LIST);
    assertEquals(attrListConsent.toString(), "");
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . The same attribute list must be returned.
   */
  @Test
  public void testUpdateAttributeList() {
    final CitizenConsent consent =
      AUCPEPSCITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUCPEPSCITIZEN.updateAttributeList(consent, ATTR_LIST);
    assertEquals(attrListConsent.toString(), ATTR_LIST.toString());
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(IStorkSession, IPersonalAttributeList)}
   * . Empty Session led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListEmptySession() {
    final IStorkSession session = mock(IStorkSession.class);
    AUCPEPSCITIZEN.updateAttributeList(session, ATTR_LIST);
  }
  
  /**
   * Test method for Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(IStorkSession, IPersonalAttributeList)}
   * . Empty personal attribute list will return the STORKAuthData with an empty
   * personal attribute list.
   */
  @Test
  public void testUpdateAttributeListSessionEmptyAttrList() {
    final IStorkSession session = mock(IStorkSession.class);
    when(session.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA);
    Assert.assertEquals(EMPTY_ATTR_LIST,
      AUCPEPSCITIZEN.updateAttributeList(session, EMPTY_ATTR_LIST));
  }
  
  /**
   * Test method for Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(IStorkSession, IPersonalAttributeList)}
   * . Null personal attribute list will return the STORKAuthData with a null
   * personal attribute list.
   */
  @Test
  public void testUpdateAttributeListSessionNullAttrList() {
    final IStorkSession session = mock(IStorkSession.class);
    when(session.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA);
    Assert.assertEquals(EMPTY_ATTR_LIST,
      AUCPEPSCITIZEN.updateAttributeList(session, null));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeList(IStorkSession, IPersonalAttributeList)}
   * . Must succeed.
   */
  @Test
  public void testUpdateAttributeListSession() {
    final IStorkSession session = mock(IStorkSession.class);
    when(session.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA);
    Assert.assertEquals(ATTR_LIST,
      AUCPEPSCITIZEN.updateAttributeList(session, ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeListValues(IStorkSession, IPersonalAttributeList)}
   * . Null Session led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListValuesNullSession() {
    AUCPEPSCITIZEN.updateAttributeListValues(null, ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeListValues(IStorkSession, IPersonalAttributeList)}
   * . Empty Session led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListValuesEmptySession() {
    final IStorkSession session = mock(IStorkSession.class);
    AUCPEPSCITIZEN.updateAttributeListValues(session, ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeListValues(IStorkSession, IPersonalAttributeList)}
   * . Null personal attribute list led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListValuesNullAttrList() {
    final IStorkSession session = mock(IStorkSession.class);
    AUCPEPSCITIZEN.updateAttributeListValues(session, null);
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeListValues(IStorkSession, IPersonalAttributeList)}
   * . Empty personal attribute list led to an unmodified attribute list.
   */
  @Test
  public void testUpdateAttributeListValuesEmptyAttrList() {
    final IStorkSession session = mock(IStorkSession.class);
    STORKAuthnRequest request= getFreshRequestWithAttrs();
    when(session.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(request);
    Assert.assertEquals(ATTR_LIST,AUCPEPSCITIZEN.updateAttributeListValues(session, EMPTY_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUCPEPSCitizen#updateAttributeListValues(IStorkSession, IPersonalAttributeList)}
   * . Must return updated Personal attribute list
   */
  @Test
  public void testUpdateAttributeListValues() {
    final IStorkSession session = mock(IStorkSession.class);
    when(session.get(PEPSParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA_NO_VALUES);
    Assert.assertEquals(
      "isAgeOver:true:[15,]:Available;age:false:[15,]:Available;",
      AUCPEPSCITIZEN.updateAttributeListValues(session, ATTR_LIST_VALUES).toString());
  }
  
}
