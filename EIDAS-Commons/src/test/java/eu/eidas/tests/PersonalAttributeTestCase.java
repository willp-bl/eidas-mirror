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
package eu.eidas.tests;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.Assert;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.EIDASStatusCode;

/**
 * The PersonalAttribute's Test Case.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.4 $, $Date: 2010-11-17 05:17:03 $
 */
public final class PersonalAttributeTestCase {
  
  /**
   * An empty attribute.
   */
  private static final PersonalAttribute EMPTYATTR = new PersonalAttribute();
  
  /**
   * An attribute with a complex value (canonicalResidenceAddress).
   */
  private static PersonalAttribute complexAttrValue = null;
  
  /**
   * An attribute with a simple value (age).
   */
  @SuppressWarnings("serial")
  private static final PersonalAttribute ATTR_VALUE = new PersonalAttribute(
    "age", true, new ArrayList<String>() {
      {
        add("15");
      }
    }, EIDASStatusCode.STATUS_AVAILABLE.toString());
  
  /**
   * Init PersonalAttributeTestCase class.
   */
  @SuppressWarnings("serial")
  @BeforeClass
  public static void runsBeforeTheTestSuite() {
    final Map<String, String> values = new HashMap<String, String>() {
      {
        put("countryCodeAddress", "PT");
        put("state", "Porto");
        put("town", "Porto");
        put("postalCode", "4100");
        put("streetName", "Avenida Sidonio Pais");
        put("streetNumber", "379");
        put("apartmentNumber", "B");
      }
    };
    
    complexAttrValue =
      new PersonalAttribute("canonicalResidenceAddress", true, values,
        EIDASStatusCode.STATUS_AVAILABLE.toString());
    
  }
  
  /**
   * Tests the {@link PersonalAttribute#toString()} method for the given simple
   * attribute value. Values must match.
   */
  @Test
  public void testToStringValues() {
    Assert.assertEquals("age:true:[15,]:Available;", ATTR_VALUE.toString());
  }
  
  /**
   * Tests the {@link PersonalAttribute#toString()} method for the given complex
   * attribute value. Values must match.
   */
  @Test
  public void testToStringComplexValues() {
    Assert.assertEquals(
      "canonicalResidenceAddress:true:[apartmentNumber=B,countryCodeAddress=PT,postalCode=4100,state=Porto,streetName=Avenida Sidonio Pais,streetNumber=379,town=Porto,]:Available;",
      complexAttrValue.toString());
  }
  
  /**
   * Tests the {@link PersonalAttribute#isEmptyStatus()} method for the given
   * empty attribute. Must return true.
   */
  @Test
  public void testToIsEmptyStatusWithNull() {
    Assert.assertTrue(EMPTYATTR.isEmptyStatus());
  }
  
  /**
   * Tests the {@link PersonalAttribute#isEmptyStatus()} method for the given
   * new attribute. Must return true.
   */
  @Test
  public void testToIsEmptyStatusWithEmptyString() {
    final PersonalAttribute attr = (PersonalAttribute) EMPTYATTR.clone();
    attr.setStatus("");
    Assert.assertTrue(attr.isEmptyStatus());
  }
  
  /**
   * Tests the {@link PersonalAttribute#isEmptyValue()} method for the given
   * empty attribute. Must return true.
   */
  @Test
  public void testToIsEmptyValueWithNull() {
    final PersonalAttribute attr = (PersonalAttribute) EMPTYATTR.clone();
    attr.setValue(null);
    Assert.assertTrue(attr.isEmptyValue());
  }
  
  /**
   * Tests the {@link PersonalAttribute#isEmptyValue()} method for the given
   * empty attribute. Must return true.
   */
  @Test
  public void testToIsEmptyValue() {
    Assert.assertTrue(EMPTYATTR.isEmptyValue());
  }
  
  /**
   * Tests the {@link PersonalAttribute#isEmptyComplexValue()} method for the
   * given empty attribute. Must return true.
   */
  @Test
  public void testToIsEmptyComplexValueWithNull() {
    final PersonalAttribute attr = (PersonalAttribute) EMPTYATTR.clone();
    attr.setComplexValue(null);
    Assert.assertTrue(attr.isEmptyComplexValue());
  }
  
  /**
   * Tests the {@link PersonalAttribute#isEmptyComplexValue()} method for the
   * given empty attribute. Must return true.
   */
  @Test
  public void testToIsEmptyComplexValueWithEmptyComplexValue() {
    Assert.assertTrue(EMPTYATTR.isEmptyComplexValue());
  }
  
  /**
   * Tests the {@link PersonalAttribute#clone()} method for the given attribute.
   * Must return true.
   */
  @Test
  public void testCloneToComplexValue() {
    Assert.assertNotSame(complexAttrValue, complexAttrValue.clone());
  }
  
  /**
   * Tests the {@link PersonalAttribute#clone()} method for the given attribute.
   * Must return true.
   */
  @Test
  public void testCloneToValue() {
    Assert.assertNotSame(ATTR_VALUE, ATTR_VALUE.clone());
  }

  @Test
  public void testGetSetSingleAttribute(){
      PersonalAttribute pat = new PersonalAttribute();
      pat.setFriendlyName("TEST");
      pat.setStatus("NA");
      PersonalAttribute pat2 = (PersonalAttribute) pat.clone();
      Assert.assertEquals(pat.getFriendlyName(), pat2.getFriendlyName());
      Assert.assertEquals(pat.getStatus(), pat2.getStatus());
      Assert.assertTrue(pat.isEmptyValue());
      Assert.assertFalse(pat.isEmptyStatus());
  }

  private static final String TEST_VAL="one";
  @Test
  public void testDisplayValue() {
    final PersonalAttribute attr = (PersonalAttribute) EMPTYATTR.clone();
    List<String> value=new ArrayList<String>();
    value.add(TEST_VAL);
    attr.setValue(value);
    Assert.assertFalse(attr.isEmptyValue());
    Assert.assertTrue(TEST_VAL.equals(attr.getDisplayValue()));
  }

}
