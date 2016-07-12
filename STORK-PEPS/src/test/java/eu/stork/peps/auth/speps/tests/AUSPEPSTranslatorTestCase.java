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

import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.cpeps.AUCPEPSTranslator;
import eu.stork.peps.auth.cpeps.tests.AUCPEPSTranslatorTestCase;
import eu.stork.peps.auth.specific.ITranslatorService;
import eu.stork.peps.auth.speps.AUSPEPSTranslator;

/**
 * Functional testing class to {@link AUSPEPSTranslator}.
 * 
 * The {@link AUSPEPSTranslator} and {@link AUCPEPSTranslator} classes use
 * {@link ITranslatorService} implementation, and as we already tested the fail
 * cases in the {@link AUCPEPSTranslatorTestCase} test case, we will just
 * develop the success test cases.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 * @version $Revision: $, $Date:$
 */
public class AUSPEPSTranslatorTestCase {
  
  /**
   * Stork Personal Attribute List with dummy attribute values.
   */
  private static IPersonalAttributeList STORK_ATTR_LIST =
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
   * Initialising class variables.
   * 
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void runBeforeClass() throws Exception {
    STORK_ATTR_LIST
      .populate("dateOfBirth:true:[2011-11-11,]:NotAvailable;age:false:[15,]:Available;");
    
    NATIVE_ATTR_LIST
      .populate("DataNascimento:true:[2011-11-11,]:NotAvailable;Idade:false:[15,]:Available;");
    NATIVE_ATTR_LIST_VALUES
      .populate("DataNascimento:true:[11/11/2011,]:NotAvailable;Idade:false:[15,]:Available;");
    
  }
  
  /**
   * Test method for
   * {@link AUSPEPSTranslator#normaliseAttributeNamesToStork(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesToStork() {
    final AUSPEPSTranslator auspepsTrans = new AUSPEPSTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesToStork(NATIVE_ATTR_LIST))
      .thenReturn(STORK_ATTR_LIST);
    
    auspepsTrans.setSpecPeps(mockSpecific);
    assertSame(STORK_ATTR_LIST,
      auspepsTrans.normaliseAttributeNamesToStork(NATIVE_ATTR_LIST));
  }
  
  /**
   * Test method for
   * {@link AUSPEPSTranslator#normaliseAttributeValuesToStork(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeValuesToStork() {
    final AUSPEPSTranslator auspepsTrans = new AUSPEPSTranslator();
    
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeValuesToStork(NATIVE_ATTR_LIST_VALUES))
      .thenReturn(STORK_ATTR_LIST);
    
    auspepsTrans.setSpecPeps(mockSpecific);
    assertSame(STORK_ATTR_LIST,
      auspepsTrans.normaliseAttributeValuesToStork(NATIVE_ATTR_LIST_VALUES));
  }
  
  /**
   * Test method for
   * {@link AUSPEPSTranslator#normaliseAttributeNamesFromStork(IPersonalAttributeList)}
   * . Must Succeed.
   */
  @Test
  public void testNormaliseAttributeNamesFromStork() {
    final AUSPEPSTranslator aucpepsTrans = new AUSPEPSTranslator();
    final ITranslatorService mockSpecific = mock(ITranslatorService.class);
    when(mockSpecific.normaliseAttributeNamesFromStork(STORK_ATTR_LIST))
      .thenReturn(NATIVE_ATTR_LIST);
    
    aucpepsTrans.setSpecPeps(mockSpecific);
    assertSame(NATIVE_ATTR_LIST,
      aucpepsTrans.normaliseAttributeNamesFromStork(STORK_ATTR_LIST));
  }
  
}
