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
import java.util.Iterator;
import java.util.Map;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASStatusCode;

/**
 * The PersonalAttributeList's Test Case.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.5 $, $Date: 2010-11-17 05:17:02 $
 */
public final class PersonalAttributeListTestCase {
  
  /**
   * isAgeOver constant value.
   */
  private static final String ISAGEOVER_CONS = "isAgeOver";
  
  /**
   * An empty attribute.
   */
  @SuppressWarnings("unused")
  private static final PersonalAttributeList EMPTY_ATTR_LIST =
    new PersonalAttributeList(0);
  
  /**
   * An attribute with a complex value (canonicalResidenceAddress).
   */
  private static PersonalAttribute complexAttrValue = null;
  
  /**
   * Simple attribute value list string.
   */
  private static final String SIMPLE_ATTRLIST =
    "isAgeOver:true:[15,]:Available;";
  
  /**
   * Simple attribute value list string.
   */
  private static final String SIMPLE_ATTRLIST2 =
    "isAgeOver:true:[18,]:Available;";
  
  /**
   * Simple attribute value list string.
   **/
    private static final String SIMPLE_ATTRLIST3 = "isAgeOver:true:[15,]:Available;isAgeOver:true:[18,]:Available;";

  /**
   * Simple attribute value list string.
   */
  private static final String COMPLEX_ATTRLIST =
    "canonicalResidenceAddress:true:[postalCode=4100,apartmentNumber=Ed. B,"
    + "state=Porto,countryCodeAddress=PT,streetNumber=379,"
    + "streetName=Avenida Sidonio Pais,town=Porto,]:Available;";
  /**
   * Mix attribute list string.
   */
  private static final String STR_MIX_ATTR_LIST =
    "isAgeOver:true:[15,]:Available;canonicalResidenceAddress:true:["
    + "postalCode=4100,apartmentNumber=Ed.B,state=Porto,countryCodeAddress=PT,"
    + "streetNumber=379,streetName=Avenida Sidonio Pais,town=Porto,]:"
    + "Available;";
  
  /**
   * Attribute List example.
   */
  @SuppressWarnings({ "serial" })
  private static final PersonalAttribute ATTR_VALUE = new PersonalAttribute(
    "age", true, new ArrayList<String>() {
      {
        add("15");
      }
    }, EIDASStatusCode.STATUS_AVAILABLE.toString());
  
  /**
   * Init PersonalAttributeListTestCase class.
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
        put("apartmentNumber", "Ed. B");
      }
    };
    
    complexAttrValue =
      new PersonalAttribute("canonicalResidenceAddress", true, values,
        EIDASStatusCode.STATUS_AVAILABLE.toString());
    
  }
  
  /**
   * Testing Personal Attribute List add method. Personal Attribute list must be
   * size 1 - Simple attribute.
   */
  @Test
  public void testAddSimpleAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(ATTR_VALUE);
    Assert.assertTrue(attrList.size() == 1);
  }
  
  /**
   * Testing Personal Attribute List add method. Personal Attribute list must be
   * size 1 - Complex attribute.
   */
  @Test
  public void testAddCompleAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(complexAttrValue);
    Assert.assertTrue(attrList.size() == 1);
  }
  
  /**
   * Testing Personal Attribute List add method. Personal Attribute list must be
   * size 0 - no attribute.
   */
  @Test
  public void testAddNull() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(null);
    Assert.assertTrue(attrList.size() == 0);
  }
  
  /**
   * Testing Personal Attribute List add method. Same attribute name added
   * twice. Personal Attribute list must be size 2 - IsAgeOver attribute added
   * twice.
   */
  @SuppressWarnings("serial")
  @Test
  public void testAddSameAttrName() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("18");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(attrValueUnder);
    attrList.add(attrValueOver);
    Assert.assertTrue(attrList.size() == 2);
  }
  
  /**
   * Testing Personal Attribute List add method. Same attribute name added
   * twice. Personal Attribute list must be size 2 - IsAgeOver attribute added
   * twice.
   */
  @SuppressWarnings("serial")
  @Test
  public void testAddSameAttrNameEmpty() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(attrValueUnder);
    attrList.add(attrValueOver);
    Assert.assertTrue(attrList.size() == 2);
  }
  
  /**
   * Testing Personal Attribute List put method. Personal Attribute list must be
   * size 1 - Simple Value.
   */
  @Test
  public void testPutSimpleAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.put(ATTR_VALUE.getName(), ATTR_VALUE);
    Assert.assertTrue(attrList.size() == 1);
  }
  
  /**
   * Testing Personal Attribute List put method. Personal Attribute list must be
   * size 1 - Complex Value.
   */
  @Test
  public void testPutComplexAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.put(ATTR_VALUE.getName(), complexAttrValue);
    Assert.assertTrue(attrList.size() == 1);
  }
  
  /**
   * Testing Personal Attribute List put method. Personal Attribute list must be
   * size 0 - no attribute.
   */
  @Test
  public void testPutNull() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.put("", null);
    Assert.assertTrue(attrList.size() == 0);
  }
  
  /**
   * Testing Personal Attribute List put method. Personal Attribute list must be
   * size 2 - IsAgeOver attribute added twice.
   */
  @SuppressWarnings("serial")
  @Test
  public void testPutSameAttrName() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("18");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.put(attrValueUnder.getName(), attrValueUnder);
    attrList.put(attrValueOver.getName(), attrValueOver);
    Assert.assertTrue(attrList.size() == 2);
  }
  
  /**
   * Testing Personal Attribute List put method. Personal Attribute list must be
   * size 2 - IsAgeOver attribute added twice.
   */
  @SuppressWarnings("serial")
  @Test
  public void testPutSameAttrNameEmpty() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.put(attrValueUnder.getName(), attrValueUnder);
    attrList.put(attrValueOver.getName(), attrValueOver);
    Assert.assertTrue(attrList.size() == 2);
  }
  
  /**
   * Testing Personal Attribute List get method. Personal Attribute list must be
   * size 1 - Simple attribute.
   */
  @Test
  public void testGetSimpleAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(ATTR_VALUE);
    Assert.assertEquals(ATTR_VALUE, attrList.get(ATTR_VALUE.getName()));
  }
  
  /**
   * Testing Personal Attribute List add method. Personal Attribute list must be
   * size 1 - Complex attribute.
   */
  @Test
  public void testGetCompleAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(complexAttrValue);
    Assert.assertEquals(complexAttrValue.toString(),
      attrList.get(complexAttrValue.getName()).toString());
  }
  
  /**
   * Testing Personal Attribute List get method. Personal Attribute list must be
   * size 2 - IsAgeOver attribute.
   */
  @SuppressWarnings("serial")
  @Test
  public void testGetIsAgeOverAttr() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("18");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(attrValueUnder);
    attrList.add(attrValueOver);
    Assert.assertEquals(SIMPLE_ATTRLIST,
      attrList.get(attrValueUnder.getName()).toString());
    Assert.assertEquals(SIMPLE_ATTRLIST2,
      attrList.get(attrValueOver.getName()).toString());
  }
  
  /**
   * Testing Personal Attribute List populate method. Personal Attribute list
   * must be size 1 - Simple attribute.
   */
  @Test
  public void testPopulateSimpleAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.populate(SIMPLE_ATTRLIST);
    Assert.assertTrue(attrList.size() == 1);
  }
  
  /**
   * Testing Personal Attribute List populate method. Personal Attribute list
   * must be size 1 - Complex attribute.
   */
  @Test
  public void testPopulateComplexAttr() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.populate(COMPLEX_ATTRLIST);
    Assert.assertTrue(attrList.size() == 1);
  }
  
  /**
   * Testing Personal Attribute List populate method. Personal Attribute list
   * must be size 1 - Simple and Complex attribute.
   */
  @Test
  public void testPopulateMixAttrs() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.populate(STR_MIX_ATTR_LIST);
    Assert.assertTrue(attrList.size() == 2);
  }
  
  /**
   * Testing Personal Attribute List toString method using add.
   */
  @SuppressWarnings("serial")
  @Test
  public void testToStringFromAdd() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("18");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(attrValueUnder);
    attrList.add(attrValueOver);
    Assert.assertTrue(attrList.toString().contains(SIMPLE_ATTRLIST));
    Assert.assertTrue(attrList.toString().contains(SIMPLE_ATTRLIST2));
  }
  
  /**
   * Testing Personal Attribute List toString method using put.
   * 
   */
  @SuppressWarnings("serial")
  @Test
  public void testToStringFromPut() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("18");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.put(attrValueUnder.getName(), attrValueUnder);
    attrList.put(attrValueOver.getName(), attrValueOver);
      Assert.assertTrue(attrList.toString().contains(SIMPLE_ATTRLIST));
      Assert.assertTrue(attrList.toString().contains(SIMPLE_ATTRLIST2));
  }
  
  /**
   * Testing Personal Attribute List toString method using populate.
   */
  @Test
  public void testToStringFromSimplePopulate() {
    final String strAttrList = "isAgeOver:true";
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.populate(strAttrList);
    Assert.assertEquals("isAgeOver:true:[]:;", attrList.toString());
  }
  
  /**
   * Testing Personal Attribute List toString method using populate.
   */
  @Test
  public void testToStringFromPopulate() {
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.populate(SIMPLE_ATTRLIST3);
    Assert.assertEquals(SIMPLE_ATTRLIST3, attrList.toString());
  }
  
  /**
   * Testing Personal Attribute List populate method, with invalid values.
   */
  @Test
  public void testPopulateWithInvalidValuesFormat() {
    final PersonalAttributeList pal = new PersonalAttributeList();
    pal.populate("name:type:values:status;");
    Assert.assertEquals(pal, new PersonalAttributeList());
  }
  
  /**
   * Testing Personal Attribute List populate method, with invalid format.
   */
  @Test
  public void testPopulateWithInvalidFormat() {
    
    final PersonalAttributeList pal = new PersonalAttributeList();
    pal.populate("name:type::status;");
    Assert.assertEquals(pal, new PersonalAttributeList());
  }
  
  /**
   * Testing Personal Attribute List clone method using add.
   */
  @SuppressWarnings("serial")
  @Test
  public void testCloneFromAdd() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("18");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.add(attrValueUnder);
    attrList.add(attrValueOver);
    Assert.assertNotSame(attrList, attrList.clone());
  }
  
  /**
   * Testing Personal Attribute List clone method using put.
   */
  @SuppressWarnings("serial")
  @Test
  public void testCloneFromPut() {
    final PersonalAttribute attrValueUnder =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("15");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    
    final PersonalAttribute attrValueOver =
      new PersonalAttribute(ISAGEOVER_CONS, true, new ArrayList<String>() {
        {
          add("18");
        }
      }, EIDASStatusCode.STATUS_AVAILABLE.toString());
    final PersonalAttributeList attrList = new PersonalAttributeList(1);
    attrList.put(attrValueUnder.getName(), attrValueUnder);
    attrList.put(attrValueOver.getName(), attrValueOver);
    Assert.assertNotSame(attrList, attrList.clone());
  }
  
  /**
   * Testing Personal Attribute List clone method using populate.
   */
  @Test
  public void testCloneFromPopulate() {
    final PersonalAttributeList pal = new PersonalAttributeList();
    pal.populate(SIMPLE_ATTRLIST3);
    Assert.assertNotSame(pal, pal.clone());
  }
  
  /**
   * Testing Personal Attribute List iterator.
   */
  @Test
  public void testIterator() {
    final PersonalAttributeList pal = new PersonalAttributeList();
    pal.populate(SIMPLE_ATTRLIST3);
    final Iterator<PersonalAttribute> itAttr = pal.iterator();
    while (itAttr.hasNext()) {
      final PersonalAttribute attr = itAttr.next();
      Assert.assertEquals(ISAGEOVER_CONS, attr.getName());
    }
  }
}
