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

import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.specific.ITranslatorService;
import eu.eidas.node.auth.connector.AUCONNECTORTranslator;
import eu.eidas.node.auth.service.AUSERVICETranslator;
import eu.eidas.node.auth.service.tests.AUSERVICETranslatorTestCase;

/**
 * Functional testing class to {@link AUCONNECTORTranslator}.
 * 
 * The {@link AUCONNECTORTranslator} and {@link AUSERVICETranslator} classes use
 * {@link ITranslatorService} implementation, and as we already tested the fail
 * cases in the {@link AUSERVICETranslatorTestCase} test case, we will just
 * develop the success test cases.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUCONNECTORTranslatorTestCase {
  
  /**
   * Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList EIDAS_ATTR_LIST =
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
   * Initialising class variables.
   * 
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void runBeforeClass() throws Exception {
    EIDAS_ATTR_LIST
      .populate("dateOfBirth:true:[2011-11-11,]:NotAvailable;age:false:[15,]:Available;");
    
    NATIVE_ATTR_LIST
      .populate("DataNascimento:true:[2011-11-11,]:NotAvailable;Idade:false:[15,]:Available;");
    NATIVE_ATTR_LIST_VALUES
      .populate("DataNascimento:true:[11/11/2011,]:NotAvailable;Idade:false:[15,]:Available;");
    
  }
  
  /**
   * Test method for
   * {@link AUCONNECTORTranslator#normaliseAttributeNamesToFormat(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesToFormat() {
    final AUCONNECTORTranslator auconnectorTrans = new AUCONNECTORTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesTo(NATIVE_ATTR_LIST))
      .thenReturn(EIDAS_ATTR_LIST);
    
    auconnectorTrans.setSpecNode(mockSpecific);
    assertSame(EIDAS_ATTR_LIST,
      auconnectorTrans.normaliseAttributeNamesToFormat(NATIVE_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUCONNECTORTranslator#normaliseAttributeValuesToFormat(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeValuesToFormat() {
    final AUCONNECTORTranslator auconnectorTrans = new AUCONNECTORTranslator();
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeValuesTo(NATIVE_ATTR_LIST_VALUES))
      .thenReturn(EIDAS_ATTR_LIST);
    
    auconnectorTrans.setSpecNode(mockSpecific);
    assertSame(EIDAS_ATTR_LIST,
      auconnectorTrans.normaliseAttributeValuesToFormat(NATIVE_ATTR_LIST_VALUES));
  }
  
  /**
   * Test method for
   * {@link AUCONNECTORTranslator#normaliseAttributeNamesFromFormat(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesFromFormat() {
    final AUCONNECTORTranslator auserviceTrans = new AUCONNECTORTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesFrom(EIDAS_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    auserviceTrans.setSpecNode(mockSpecific);
    assertSame(NATIVE_ATTR_LIST,
      auserviceTrans.normaliseAttributeNamesFromFormat(EIDAS_ATTR_LIST));
  }
  
}
