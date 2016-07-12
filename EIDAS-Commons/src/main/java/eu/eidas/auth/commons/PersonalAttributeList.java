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
package eu.eidas.auth.commons;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is a bean used to store the information relative to the
 * PersonalAttributeList.
 * @see PersonalAttribute
 */
@SuppressWarnings("PMD")
public final class PersonalAttributeList extends
        ConcurrentHashMap<String, PersonalAttribute> implements IPersonalAttributeList {

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory
            .getLogger(PersonalAttributeList.class.getName());

    /**
     * Serial id.
     */
    private static final long serialVersionUID = 7375127363889975062L;

    /**
     * Hash with the latest fetched attribute name alias.
     */
    private final transient Map<String, Integer> latestAttrAlias =
            new HashMap<String, Integer>();

    /**
     * Hash with mapping number of alias or the attribute name.
     */
    private final transient Map<String, Integer> attrAliasNumber =
            new HashMap<String, Integer>();
    private transient List<String> insertOrder = new ArrayList<String>();

    /**
     * Obtain the insertOrder Collection
     *
     * @return defensive copy of the collection
     */
    List<String> getInsertOrder() {
        return Collections.unmodifiableList(this.insertOrder);
    }

    /**
     * Default constructor.
     */
    public PersonalAttributeList() {
        // The best practices recommend to call the super constructor.
        super();
    }

    /**
     * Constructor with initial capacity for the PersonalAttributeList size.
     *
     * @param capacity The initial capacity for the PersonalAttributeList.
     */
    public PersonalAttributeList(final int capacity) {
        super(capacity);
    }

    /**
     * {@inheritDoc}
     */
    public Iterator<PersonalAttribute> iterator() {
        return new OrderedAttributeIterator(this);
    }

    /**
     * {@inheritDoc}
     */
    public PersonalAttribute get(final Object key) {
        String attrName = (String) key;

        if (this.latestAttrAlias.containsKey(key)) {
            attrName = attrName + this.latestAttrAlias.get(key);
        } else {
            if (this.attrAliasNumber.containsKey(key)) {
                this.latestAttrAlias.put(attrName, this.attrAliasNumber.get(key));
            }
        }
        return super.get(attrName);
    }

    /**
     * {@inheritDoc}
     */
    public void add(final PersonalAttribute value) {
        if (value != null) {
            this.put(value.getName(), value);
        }
    }

    /**
     * {@inheritDoc}
     */
    public PersonalAttribute put(final String key, final PersonalAttribute val) {
        if (StringUtils.isNotEmpty(key) && val != null) {
            // Validate if attribute name already exists!
            String attrAlias = key;
            if (this.containsKey(attrAlias)) {
                if (!val.isEmptyValue() && StringUtils.isNumeric(val.getValue().get(0))) {
                    final String attrValue = val.getValue().get(0);
                    attrAlias = key + attrValue;
                    this.attrAliasNumber.put(key, Integer.valueOf(attrValue));
                } else {
                    final PersonalAttribute attr = super.get(key);
                    if (!attr.isEmptyValue()
                            && StringUtils.isNumeric(attr.getValue().get(0))) {
                        attrAlias = key + attr.getValue().get(0);
                        super.put(key, (PersonalAttribute) attr);
                        this.attrAliasNumber.put(key, null);
                    }
                }
            } else {
                insertOrder.add(key);
            }
            return super.put(attrAlias, val);
        } else {
            return null;
        }
    }

    @Override
    public PersonalAttribute remove(Object key) {
        insertOrder.remove(key);
        return super.remove(key);
    }

    /**
     * {@inheritDoc}
     */
    public void populate(final String attrList) {
        final StringTokenizer strToken =
                new StringTokenizer(attrList, EIDASValues.ATTRIBUTE_SEP.toString());

        while (strToken.hasMoreTokens()) {
            final PersonalAttribute persAttr = new PersonalAttribute();
            String[] tuples =
                    strToken.nextToken().split(EIDASValues.ATTRIBUTE_TUPLE_SEP.toString(),
                            AttributeConstants.NUMBER_TUPLES.intValue());

            // Convert to the new format if needed!
            tuples = convertFormat(tuples);

            if (AttributeUtil.hasValidTuples(tuples)) {
                final int attrValueIndex =
                        AttributeConstants.ATTR_VALUE_INDEX.intValue();
                final String tmpAttrValue =
                        tuples[attrValueIndex].substring(1,
                                tuples[attrValueIndex].length() - 1);
                final String[] vals =
                        tmpAttrValue.split(EIDASValues.ATTRIBUTE_VALUE_SEP.toString());

                persAttr.setName(tuples[AttributeConstants.ATTR_NAME_INDEX.intValue()]);
                persAttr.setIsRequired(Boolean
                        .valueOf(tuples[AttributeConstants.ATTR_TYPE_INDEX.intValue()]));
                // check if it is a complex value
                if (tuples[AttributeConstants.ATTR_NAME_INDEX.intValue()]
                        .equals(EIDASParameters.COMPLEX_ADDRESS_VALUE.toString())) {
                    persAttr.setComplexValue(createComplexValue(vals));
                } else {
                    persAttr.setValue(createValues(vals));
                }

                if (tuples.length == AttributeConstants.NUMBER_TUPLES.intValue()) {
                    persAttr.setStatus(tuples[AttributeConstants.ATTR_STATUS_INDEX
                            .intValue()]);
                }
                this.put(tuples[AttributeConstants.ATTR_NAME_INDEX.intValue()],
                        persAttr);

            } else {
                LOG.info("BUSINESS EXCEPTION : Invalid personal attribute list tuples");
            }

        }
    }

  /**
  * Returns a copy of this <tt>IPersonalAttributeList</tt> instance.
  *
  * @return The copy of this IPersonalAttributeList.
  */
  public Object clone() {
      try {
          PersonalAttributeList theClone= (PersonalAttributeList)super.clone();
          theClone.insertOrder=new ArrayList<String>(insertOrder);
          return theClone;
      } catch (CloneNotSupportedException e) {
          throw new InternalErrorEIDASException(
                  EIDASUtil.getConfig(EIDASErrors.INTERNAL_ERROR.errorCode()),
                  EIDASUtil.getConfig(EIDASErrors.INTERNAL_ERROR.errorMessage()), e);
      }
  }

  /**
   * Creates a string in the following format.
   *
   * attrName:attrType:[attrValue1,attrValue2=attrComplexValue]:attrStatus;
   *
   * @return {@inheritDoc}
   */
  @Override
  public String toString() {
      final StringBuilder strBuilder = new StringBuilder();
      final Iterator<String> iteratorInsertOrder = insertOrder.iterator();
      while (iteratorInsertOrder.hasNext()) {
          String key = iteratorInsertOrder.next();
          final PersonalAttribute attr = get(key);
          strBuilder.append(attr.toString());
          if (isNumberAlias(key)) {
              strBuilder.append(get(key).toString());
          }
      }
      return strBuilder.toString();
  }

    /**
     * Validates and creates the attribute's complex values.
     *
     * @param values The complex values.
     * @return The {@link Map} with the complex values.
     * @see Map
     */
    private Map<String, String> createComplexValue(final String[] values) {
        final Map<String, String> complexValue = new HashMap<String, String>();
        for (final String val : values) {
            final String[] tVal = val.split("=");
            if (StringUtils.isNotEmpty(val) && tVal.length == 2) {
                complexValue.put(tVal[0], AttributeUtil.unescape(tVal[1]));
            }
        }
        return complexValue;
    }

    /**
     * Validates and creates the attribute values.
     *
     * @param vals The attribute values.
     * @return The {@link List} with the attribute values.
     * @see List
     */
    private List<String> createValues(final String[] vals) {
        final List<String> values = new ArrayList<String>();
        for (final String val : vals) {
            if (StringUtils.isNotEmpty(val)) {
                values.add(AttributeUtil.unescape(val));
            }
        }
        return values;
    }

    //////////////////
    /**
     * Converts the attribute tuple (attrName:attrType...) to the new format.
     *
     * @param tuples The attribute tuples to convert.
     * @return The attribute tuples in the new format.
     */
    private String[] convertFormat(final String[] tuples) {
        final String[] newFormatTuples =
                new String[AttributeConstants.NUMBER_TUPLES.intValue()];
        if (tuples != null) {
            System.arraycopy(tuples, 0, newFormatTuples, 0, tuples.length);

            for (int i = tuples.length; i < newFormatTuples.length; i++) {
                if (i == AttributeConstants.ATTR_VALUE_INDEX.intValue()) {
                    newFormatTuples[i] = "[]";
                } else {
                    newFormatTuples[i] = "";
                }
            }
        }
        return newFormatTuples;
    }

    public boolean isNumberAlias(String key) {
        return this.attrAliasNumber.containsKey(key);
    }

}
