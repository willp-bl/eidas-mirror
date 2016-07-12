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

import eu.eidas.auth.commons.CitizenConsent;
import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.node.auth.service.AUSERVICECitizen;
import eu.eidas.node.auth.service.ISERVICECitizenService;
import eu.eidas.node.auth.service.ISERVICESAMLService;

import org.junit.runners.MethodSorters;

/**
 * Functional testing class to {@link AUSERVICECitizen}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
@FixMethodOrder(MethodSorters.JVM)
public final class AUSERVICECitizenTestCase {
  
  /**
   * Citizen Consent Object
   */
  private static ISERVICECitizenService AUSERVICECITIZEN = new AUSERVICECitizen();
  
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
   * Empty EIDASAuthnRequest object.
   */
  private static EIDASAuthnRequest EMPTY_AUTH_DATA = new EIDASAuthnRequest();
  
  /**
   * EIDASAuthnRequest object.
   */
  private static EIDASAuthnRequest AUTH_DATA = new EIDASAuthnRequest();
  
  /**
   * EIDASAuthnRequest object with no attribute values.
   */
  private static EIDASAuthnRequest AUTH_DATA_NO_VALUES =
    new EIDASAuthnRequest();
  
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

  private EIDASAuthnRequest getFreshRequestWithAttrs(){
    EIDASAuthnRequest request=new EIDASAuthnRequest();
    request.setPersonalAttributeList(ATTR_LIST);
    return request;
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#getCitizenConsent(Map, IPersonalAttributeList)}.
   * Using an empty parameters.
   */
  @Test
  public void testGetCitizenConsentEmptyParameters() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(EMPTY_PARAMETERS, ATTR_LIST);
    assertArrayEquals(consent.getMandatoryList().toArray(), EMPTY_STR_ARRAY);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#getCitizenConsent(Map, IPersonalAttributeList)}.
   * Using and empty personal attribute list.
   */
  @Test
  public void testGetCitizenConsentEmptyAttrList() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(PARAMETERS, EMPTY_ATTR_LIST);
    assertArrayEquals(consent.getMandatoryList().toArray(), EMPTY_STR_ARRAY);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#getCitizenConsent(Map, IPersonalAttributeList)} .
   */
  @Test
  public void testGetCitizenConsent() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    assertArrayEquals(consent.getMandatoryList().toArray(),
      new String[] { "isAgeOver" });
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#processCitizenConsent(CitizenConsent, EIDASAuthnRequest, String, ISERVICESAMLService)}
   * . Testing empty EIDASAuthnRequest and no exception should be thrown.
   */
  @Test
  public void testProcessCitizenConsentEmptyAuthData() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    
    final ISERVICESAMLService mockedServiceSAMLService =
      mock(ISERVICESAMLService.class);
    
    when(
      mockedServiceSAMLService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUSERVICECITIZEN.processCitizenConsent(consent, EMPTY_AUTH_DATA, USER_IP,
      mockedServiceSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#processCitizenConsent(CitizenConsent, EIDASAuthnRequest, String, ISERVICESAMLService)}
   * . Testing empty Consent and no exception should be thrown.
   */
  @Test
  public void testProcessCitizenConsentEmptyConsent() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    
    final ISERVICESAMLService mockedServiceSAMLService =
      mock(ISERVICESAMLService.class);
    
    when(
      mockedServiceSAMLService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUSERVICECITIZEN.processCitizenConsent(consent, EMPTY_AUTH_DATA, USER_IP,
      mockedServiceSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#processCitizenConsent(CitizenConsent, EIDASAuthnRequest, String, ISERVICESAMLService)}
   * . No exception should be thrown.
   */
  @Test
  public void testProcessCitizenConsent() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    
    final ISERVICESAMLService mockedServiceSAMLService =
      mock(ISERVICESAMLService.class);
    
    when(
      mockedServiceSAMLService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUSERVICECITIZEN.processCitizenConsent(consent, EMPTY_AUTH_DATA, USER_IP,
      mockedServiceSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#processCitizenConsent(CitizenConsent, EIDASAuthnRequest, String, ISERVICESAMLService)}
   * . An ServiceException must be thrown.
   */
  @Test(expected = EIDASServiceException.class)
  public void testProcessCitizenConsentWrongConsent() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    final Properties configs = new Properties();
    configs.put(EIDASErrors.CITIZEN_RESPONSE_MANDATORY.errorCode(), "202007");
    configs.put(EIDASErrors.CITIZEN_RESPONSE_MANDATORY.errorMessage(),
      "no.consent.mand.attr");
    EIDASUtil.createInstance(configs);
    
    final ISERVICESAMLService mockedServiceSAMLService =
      mock(ISERVICESAMLService.class);
    
    when(
      mockedServiceSAMLService.generateErrorAuthenticationResponse(
        (EIDASAuthnRequest) any(), anyString(), anyString(), anyString(),
        anyString(), anyBoolean())).thenReturn(new byte[0]);
    
    AUSERVICECITIZEN.processCitizenConsent(consent, AUTH_DATA, USER_IP,
      mockedServiceSAMLService);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . Testing and empty Consent type and a personal attribute list must be
   * returned.
   */
  @Test
  public void testUpdateAttributeListEmptyConsent() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(EMPTY_PARAMETERS, EMPTY_ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUSERVICECITIZEN.updateAttributeList(consent, ATTR_LIST);
    assertEquals(attrListConsent.toString(), "isAgeOver:true:[15,]:Available;");
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . Testing an empty attribute list and an empty attribute list must be
   * returned.
   */
  @Test
  public void testUpdateAttributeListEmptyAttrList() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUSERVICECITIZEN.updateAttributeList(consent, EMPTY_ATTR_LIST);
    assertEquals(attrListConsent.toString(), "");
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . Testing an empty attribute list and a empty consent type: an empty
   * personal attribute list must be returned.
   */
  @Test
  public void testUpdateAttributeListEmpty() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUSERVICECITIZEN.updateAttributeList(consent, EMPTY_ATTR_LIST);
    assertEquals(attrListConsent.toString(), "");
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeList(CitizenConsent, IPersonalAttributeList)}
   * . The same attribute list must be returned.
   */
  @Test
  public void testUpdateAttributeList() {
    final CitizenConsent consent =
      AUSERVICECITIZEN.getCitizenConsent(PARAMETERS, ATTR_LIST);
    final IPersonalAttributeList attrListConsent =
      AUSERVICECITIZEN.updateAttributeList(consent, ATTR_LIST);
    assertEquals(attrListConsent.toString(), ATTR_LIST.toString());
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeList(IEIDASSession, IPersonalAttributeList)}
   * . Empty Session led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListEmptySession() {
    final IEIDASSession session = mock(IEIDASSession.class);
    AUSERVICECITIZEN.updateAttributeList(session, ATTR_LIST);
  }
  
  /**
   * Test method for Test method for
   * {@link AUSERVICECitizen#updateAttributeList(IEIDASSession, IPersonalAttributeList)}
   * . Empty personal attribute list will return the EIDASAuthnRequest with an empty
   * personal attribute list.
   */
  @Test
  public void testUpdateAttributeListSessionEmptyAttrList() {
    final IEIDASSession session = mock(IEIDASSession.class);
    when(session.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA);
    Assert.assertEquals(EMPTY_ATTR_LIST,
      AUSERVICECITIZEN.updateAttributeList(session, EMPTY_ATTR_LIST));
  }
  
  /**
   * Test method for Test method for
   * {@link AUSERVICECitizen#updateAttributeList(IEIDASSession, IPersonalAttributeList)}
   * . Null personal attribute list will return the EIDASAuthnRequest with a null
   * personal attribute list.
   */
  @Test
  public void testUpdateAttributeListSessionNullAttrList() {
    final IEIDASSession session = mock(IEIDASSession.class);
    when(session.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA);
    Assert.assertEquals(EMPTY_ATTR_LIST,
      AUSERVICECITIZEN.updateAttributeList(session, null));
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeList(IEIDASSession, IPersonalAttributeList)}
   * . Must succeed.
   */
  @Test
  public void testUpdateAttributeListSession() {
    final IEIDASSession session = mock(IEIDASSession.class);
    when(session.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA);
    Assert.assertEquals(ATTR_LIST,
      AUSERVICECITIZEN.updateAttributeList(session, ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeListValues(IEIDASSession, IPersonalAttributeList)}
   * . Null Session led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListValuesNullSession() {
    AUSERVICECITIZEN.updateAttributeListValues(null, ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeListValues(IEIDASSession, IPersonalAttributeList)}
   * . Empty Session led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListValuesEmptySession() {
    final IEIDASSession session = mock(IEIDASSession.class);
    AUSERVICECITIZEN.updateAttributeListValues(session, ATTR_LIST);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeListValues(IEIDASSession, IPersonalAttributeList)}
   * . Null personal attribute list led to a NullPointerException.
   */
  @Test(expected = NullPointerException.class)
  public void testUpdateAttributeListValuesNullAttrList() {
    final IEIDASSession session = mock(IEIDASSession.class);
    AUSERVICECITIZEN.updateAttributeListValues(session, null);
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeListValues(IEIDASSession, IPersonalAttributeList)}
   * . Empty personal attribute list led to an unmodified attribute list.
   */
  @Test
  public void testUpdateAttributeListValuesEmptyAttrList() {
    final IEIDASSession session = mock(IEIDASSession.class);
    EIDASAuthnRequest request= getFreshRequestWithAttrs();
    when(session.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(request);
    Assert.assertEquals(ATTR_LIST,AUSERVICECITIZEN.updateAttributeListValues(session, EMPTY_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUSERVICECitizen#updateAttributeListValues(IEIDASSession, IPersonalAttributeList)}
   * . Must return updated Personal attribute list
   */
  @Test
  public void testUpdateAttributeListValues() {
    final IEIDASSession session = mock(IEIDASSession.class);
    when(session.get(EIDASParameters.AUTH_REQUEST.toString())).thenReturn(
      AUTH_DATA_NO_VALUES);
    Assert.assertEquals(
      "isAgeOver:true:[15,]:Available;age:false:[15,]:Available;",
      AUSERVICECITIZEN.updateAttributeListValues(session, ATTR_LIST_VALUES).toString());
  }
  
}
