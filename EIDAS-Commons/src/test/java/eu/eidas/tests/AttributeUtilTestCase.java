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

import org.junit.Assert;
import org.junit.Test;

import eu.eidas.auth.commons.AttributeUtil;
import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.PersonalAttributeString;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The AttributeUtil's Test Case.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com
 *
 * @version $Revision: $, $Date: $
 */
public final class AttributeUtilTestCase {

  /**
   * Empty String to be used on the tests.
   */
  private static final String EMPTY_STRING = "";

  /**
   * Tuple value sample to be used on the tests.
   */
  private static final String[] TUPLE_STRING = new String[] { "age", "true",
    "[18]", "Available" };

  /**
   * Complex value to be used on escape/unescape tests.
   */
  private static final String COMPLEX_VAL = "postalCode=4100,"
    + "apartmentNumber=A,state=Porto,countryCodeAddress=PT,streetNumber=379,"
    + "streetName=Avenida Sidonio Pais,town=Porto,";

  /**
   * Escaped Complex value to be used on escape/unescape tests.
   */
  private static final String ESC_COMPLEX_VAL = "postalCode=4100%44"
    + "apartmentNumber=A%44state=Porto%44countryCodeAddress=PT%44"
    + "streetNumber=379%44streetName=Avenida Sidonio Pais%44town=Porto%44";

  /**
   * Simple value to be used on escape/unescape tests.
   */
  private static final String SIMPLE_VAL = "Avenida da Boavista, Porto";

  /**
   * Escaped simple value to be used on escape/unescape tests.
   */
  private static final String ESC_SIMPLE_VAL = "Avenida da Boavista%44 Porto";

  /**
   * Simple text to be used on escape/unescape tests. Must match the escaped
   * text.
   */
  private static final String SIMPLE_TEXT = "John Doe";

  /**
   * Tests the {@link AttributeUtil#escape(String)} method for the given complex
   * attribute value (canonical address' example attribute value).
   */
  @Test
  public void testEscapeSpecialCharsComplexVal() {
    Assert.assertEquals(AttributeUtil.escape(COMPLEX_VAL), ESC_COMPLEX_VAL);
  }

  /**
   * Tests the {@link AttributeUtil#escape(String)} method for the given
   * attribute value.
   */
  @Test
  public void testEscapeSpecialCharsVal() {
    Assert.assertEquals(AttributeUtil.escape(SIMPLE_VAL), ESC_SIMPLE_VAL);
  }

  /**
   * Tests the {@link AttributeUtil#escape(String)} method for the given simple
   * text: no special characters to escape.
   */
  @Test
  public void testEscapeNormalChars() {
    Assert.assertEquals(AttributeUtil.escape(SIMPLE_TEXT), SIMPLE_TEXT);
  }

  /**
   * Tests the {@link AttributeUtil#unescape(String)} method for the given
   * escape complex attribute value (canonical address' example attribute
   * value).
   */
  @Test
  public void testUnescapeSpecialCharsComplexVal() {
    Assert.assertEquals(AttributeUtil.unescape(ESC_COMPLEX_VAL), COMPLEX_VAL);
  }

  /**
   * Tests the {@link AttributeUtil#escape(String)} method for the given escape
   * attribute value.
   */
  @Test
  public void testUnescapeSpecialCharsVal() {
    Assert.assertEquals(AttributeUtil.unescape(ESC_SIMPLE_VAL), SIMPLE_VAL);
  }

  /**
   * Tests the {@link AttributeUtil#escape(String)} method for the given simple
   * text: no special characters to unescape.
   */
  @Test
  public void testUnescapeNormalChars() {
    Assert.assertEquals(AttributeUtil.unescape(SIMPLE_TEXT), SIMPLE_TEXT);
  }

  @Test
  public void testAppendIfNullEmptyStr(){
      final StringBuilder strBuilder = new StringBuilder(SIMPLE_TEXT);
      AttributeUtil.appendIfNotNull(strBuilder, null);
      Assert.assertEquals(strBuilder.toString(), SIMPLE_TEXT);
  }
  /**
   * Tests the {@link AttributeUtil#appendIfNotNull(StringBuilder, Object)}
   * method for the given empty string.
   */
  @Test
  public void testAppendIfNotNullEmptyStr() {
    final StringBuilder strBuilder = new StringBuilder(SIMPLE_TEXT);
    AttributeUtil.appendIfNotNull(strBuilder, EMPTY_STRING);
    Assert.assertEquals(strBuilder.toString(), SIMPLE_TEXT);
  }

  /**
   * Tests the {@link AttributeUtil#appendIfNotNull(StringBuilder, Object)}
   * method for the given string.
   */
  @Test
  public void testAppendIfNotNullStr() {
    final StringBuilder strBuilder = new StringBuilder();
    AttributeUtil.appendIfNotNull(strBuilder, SIMPLE_TEXT);
    Assert.assertEquals(strBuilder.toString(), SIMPLE_TEXT);
  }

  /**
   * Tests the {@link AttributeUtil#appendIfNotNull(StringBuilder, Object)}
   * method for the given null value.
   */
  @Test
  public void testAppendIfNotNull() {
    final StringBuilder strBuilder = new StringBuilder();
    AttributeUtil.appendIfNotNull(strBuilder, null);
    Assert.assertEquals(strBuilder.toString(), EMPTY_STRING);
  }

  /**
   * Tests the {@link AttributeUtil#listToString(List, String)} method for the
   * given List with two values.
   */
  @Test
  public void testListToStringTwoVals() {
    final List<String> vals = new ArrayList<String>();
    vals.add(SIMPLE_VAL);
    vals.add(SIMPLE_TEXT);

    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());
    strBuilder.append(SIMPLE_TEXT);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());

    Assert.assertEquals(
      AttributeUtil.listToString(vals,
              EIDASValues.ATTRIBUTE_VALUE_SEP.toString()), strBuilder.toString());
  }

  /**
   * Tests the {@link AttributeUtil#listToString(List, String)} method for the
   * given List with one values.
   */
  @Test
  public void testListToStringOneVal() {
    final List<String> vals = new ArrayList<String>();
    vals.add(SIMPLE_VAL);

    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());

    Assert.assertEquals(
      AttributeUtil.listToString(vals,
              EIDASValues.ATTRIBUTE_VALUE_SEP.toString()), strBuilder.toString());
  }

  /**
   * Tests the {@link AttributeUtil#listToString(List, String)} method for the
   * given List with one values.
   */
  @Test
  public void testListToStringOneNullVal() {
    final List<String> vals = new ArrayList<String>();
    vals.add(null);

    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());

    Assert.assertNotSame(
            AttributeUtil.listToString(vals,
                    EIDASValues.ATTRIBUTE_VALUE_SEP.toString()), strBuilder.toString());
  }

  /**
   * Tests the {@link AttributeUtil#listToString(List, String)} method for the
   * given List with one value.
   */
  @Test
  public void testListToStringEmptyVal() {
    final List<String> vals = new ArrayList<String>();

    final StringBuilder strBuilder = new StringBuilder();

    Assert.assertEquals(
      AttributeUtil.listToString(vals,
              EIDASValues.ATTRIBUTE_VALUE_SEP.toString()), strBuilder.toString());
  }

  /**
   * Tests the {@link AttributeUtil#mapToString(java.util.Map, String)} method
   * for the given Map with one value.
   */
  @Test
  public void testMapToStringOneVal() {
    final Map<String, String> vals = new HashMap<String, String>();
    vals.put("CanonicalAddress", COMPLEX_VAL);

    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append("CanonicalAddress=");
    strBuilder.append(ESC_COMPLEX_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());

    Assert.assertEquals(AttributeUtil.mapToString(vals,
            EIDASValues.ATTRIBUTE_VALUE_SEP.toString()), strBuilder.toString());
  }

  /**
   * Tests the {@link AttributeUtil#mapToString(java.util.Map, String)} method
   * for the given empty Map.
   */
  @Test
  public void testMapToStringEmptyVal() {
    final Map<String, String> vals = new HashMap<String, String>();

    final StringBuilder strBuilder = new StringBuilder();

    Assert.assertEquals(AttributeUtil.mapToString(vals,
            EIDASValues.ATTRIBUTE_VALUE_SEP.toString()), strBuilder.toString());
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * invalid List.
   */
  @Test
  public void testIsValidValueInvalidList() {
      // Case 1 : invalid beginning list
    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append("]");
    Assert.assertFalse("Invalid beginning list", AttributeUtil.isValidValue(strBuilder.toString()));
    // case 2 : null list
    Assert.assertFalse("Null list", AttributeUtil.isValidValue(null));
    // case 3 : invalid ending list
    Assert.assertFalse("Invalid ending list", AttributeUtil.isValidValue("[,"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * empty List.
   */
  @Test
  public void testIsValidValueEmptyList() {
    Assert.assertTrue(AttributeUtil.isValidValue("[]"));
    Assert.assertTrue(AttributeUtil.isValidValue("[ ]"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * empty List.
   */
  @Test
  public void testIsValidValueEmptyCommaList() {
    Assert.assertTrue(AttributeUtil.isValidValue("[,]"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * one simple value List.
   */
  @Test
  public void testIsValidValueOneValueList() {
    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append("[");
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append("]");
    Assert.assertTrue(AttributeUtil.isValidValue(strBuilder.toString()));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * one simple value List.
   */
  @Test
  public void testIsValidValueOneValueCommaList() {
    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append("[");
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());
    strBuilder.append("]");
    Assert.assertTrue(AttributeUtil.isValidValue(strBuilder.toString()));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * one complex value List.
   */
  @Test
  public void testIsValidValueOneComplexValueList() {
    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append("[");
    strBuilder.append(ESC_COMPLEX_VAL);
    strBuilder.append("]");
    Assert.assertTrue(AttributeUtil.isValidValue(strBuilder.toString()));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * one complex value List.
   */
  @Test
  public void testIsValidValueOneComplexValueCommaList() {
    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append("[");
    strBuilder.append(ESC_COMPLEX_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());
    strBuilder.append("]");
    Assert.assertTrue(AttributeUtil.isValidValue(strBuilder.toString()));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * multi value List.
   */
  @Test
  public void testIsValidValueMultiValueList() {
    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append("[");
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());
    strBuilder.append(SIMPLE_TEXT);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());
    strBuilder.append("]");
    Assert.assertTrue(AttributeUtil.isValidValue(strBuilder.toString()));
  }

  /**
   * Tests the {@link AttributeUtil#isValidValue(String)} method for the given
   * invalid multi value List.
   */
  @Test
  public void testIsValidValueInvalidMultiValueList() {
    final StringBuilder strBuilder = new StringBuilder();
    strBuilder.append(ESC_SIMPLE_VAL);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());
    strBuilder.append(SIMPLE_TEXT);
    strBuilder.append(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());
    strBuilder.append("]");
    Assert.assertFalse(AttributeUtil.isValidValue(strBuilder.toString()));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * true type.
   */
  @Test
  public void testIsValidTypetrue() {
    Assert.assertTrue(AttributeUtil.isValidType("true"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * True type.
   */
  @Test
  public void testIsValidTypeTrue() {
    Assert.assertTrue(AttributeUtil.isValidType("True"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * TRUE type.
   */
  @Test
  public void testIsValidTypeTRUE() {
    Assert.assertTrue(AttributeUtil.isValidType("TRUE"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * invalid type.
   */
  @Test
  public void testIsValidTypeInvalidType() {
    Assert.assertFalse(AttributeUtil.isValidType("str"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * false type.
   */
  @Test
  public void testIsValidTypefalse() {
    Assert.assertTrue(AttributeUtil.isValidType("false"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * False type.
   */
  @Test
  public void testIsValidTypeFalse() {
    Assert.assertTrue(AttributeUtil.isValidType("False"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * FALSE type.
   */
  @Test
  public void testIsValidTypeFALSEVal() {
    Assert.assertTrue(AttributeUtil.isValidType("False"));
  }

  /**
   * Tests the {@link AttributeUtil#isValidType(String)} method for the given
   * null.
   */
  @Test
  public void testIsValidTypeNullVal() {
    Assert.assertFalse(AttributeUtil.isValidType(null));
  }

  /**
   * Tests the {@link AttributeUtil#hasValidTuples(String[])} method for the
   * given valid tuple.
   */
  @Test
  public void testHasValidTuples() {
    assertTrue(AttributeUtil.hasValidTuples(TUPLE_STRING));
  }

  /**
   * Tests the {@link AttributeUtil#hasValidTuples(String[])} method for the
   * given invalid tuple.
   */
  @Test
  public void testHasValidTuplesInvalid() {
    final String[] tuple = new String[]{"name", "type"};
    assertFalse(AttributeUtil.hasValidTuples(tuple));
  }

  /**
   * Tests the {@link AttributeUtil#hasValidTuples(String[])} method for the
   * given invalid tuple with valid size.
   */
  @Test
  public void testHasValidTuplesSameSizeInvalidValues() {
    final String[] tuple = new String[] { "http://www.stork.gov.eu/1.0/age", "type", "[18]", "Available"};
    assertFalse(AttributeUtil.hasValidTuples(tuple));
  }

  /**
   * Tests the {@link AttributeUtil#hasValidTuples(String[])} method for the
   * given null value.
   */
  @Test
  public void testHasValidTuplesNull() {
    assertFalse(AttributeUtil.hasValidTuples(null));
  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given attribute list..
   */
  @Test
  public void testCheckMissingMandatoryAttributes() {
    String strAttrList = "http://www.stork.gov.eu/1.0/isAgeOver:true:[18,]:Available;";
    final IPersonalAttributeList attrList = PersonalAttributeString.fromStringList(strAttrList);
    assertTrue(AttributeUtil.getMissingMandatoryAttributes(attrList).isEmpty());

  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given null value.
   */
  @Test(expected = NullPointerException.class)
  public void testCheckMissingMandatoryAttributesNullAttrList() {
    assertTrue(AttributeUtil.getMissingMandatoryAttributes(null).isEmpty());
  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given empty attribute list.
   */
  @Test
  public void testCheckMissingMandatoryAttributesEmptyAttrList() {
    final IPersonalAttributeList attrList = new PersonalAttributeList();
    assertTrue(AttributeUtil.getMissingMandatoryAttributes(attrList).isEmpty());
  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given attribute list (missing mandatory attribute).
   */
  @Test
  public void testCheckMissingMandatoryAttributesMissingAttr() {
    String strAttrList = "http://www.stork.gov.eu/1.0/isAgeOver:true:[]:NotAvailable;";
    final IPersonalAttributeList attrList = PersonalAttributeString.fromStringList(strAttrList);
    assertFalse(AttributeUtil.getMissingMandatoryAttributes(attrList).isEmpty());
  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given attribute list..
   */
  @Test
  public void testCheckMandatoryAttributes() {
    String strAttrList = "http://www.stork.gov.eu/1.0/isAgeOver:true:[18,]:Available;";
    final IPersonalAttributeList attrList = PersonalAttributeString.fromStringList(strAttrList);
    assertTrue(AttributeUtil.getMissingMandatoryAttributes(attrList).isEmpty());
  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given null value.
   */
  @Test(expected = NullPointerException.class)
  public void testCheckMandatoryAttributesNullAttrList() {
    assertTrue(AttributeUtil.getMissingMandatoryAttributes(null).isEmpty());
  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given empty attribute list.
   */
  @Test
  public void testCheckMandatoryAttributesEmptyAttrList() {
    final IPersonalAttributeList attrList = new PersonalAttributeList();
    assertTrue(AttributeUtil.getMissingMandatoryAttributes(attrList).isEmpty());
  }

  /**
   * Tests the
   * {@link AttributeUtil#getMissingMandatoryAttributes(IPersonalAttributeList)}
   * method for the given attribute list (missing mandatory attribute).
   */
  @Test
  public void testCheckMandatoryAttributesMissingAttr() {
    String strAttrList = "http://www.stork.gov.eu/1.0/isAgeOver:true:[]:NotAvailable;";
    final IPersonalAttributeList attrList = PersonalAttributeString.fromStringList(strAttrList);
    assertFalse(AttributeUtil.getMissingMandatoryAttributes(attrList).isEmpty());
  }

}
