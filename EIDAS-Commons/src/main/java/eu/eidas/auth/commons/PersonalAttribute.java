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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;

/**
 * This class is a bean used to store the information relative to the
 * PersonalAttribute.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.22 $, $Date: 2010-11-17 05:15:28 $
 */
public final class PersonalAttribute implements Serializable, Cloneable {
  
  /**
   * Unique identifier.
   */
  private static final long serialVersionUID = 2612951678412632174L;
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PersonalAttribute.class
    .getName());
  
  /**
   * Name of the personal attribute.
   */
  private String name;
  
  /**
   * Values of the personal attribute.
   */
  private List<String> value = new ArrayList<String>();
  
  /**
   * Complex values of the personal attribute.
   */
  private Map<String, String> complexValue = new ConcurrentHashMap<String, String>();
  
  /**
   * Is the personal attribute mandatory?
   */
  private transient boolean required;
  
  /**
   * Returned status of the attribute from the IdP.
   */
  private String status;
  
  /**
   * Name of the personal attribute.
   */
  private String friendlyName;

  /**
   * complete name, as set in the Name attribute of the stork:RequestedAttribute node
   */
  private String fullName;

    /**
     * set to true when the attribute is an eIDAS natural person attribute
     */
    private boolean eidasNaturalPersonAttr;
    /**
     * set to true when the attribute is an eIDAS legal person attribute
     */
    private boolean eidasLegalPersonAttr;

  /**
   * Empty Constructor.
   */
  public PersonalAttribute() {
    super();
  }
  
  /**
   * PersonalAttribute Constructor for complex values.
   * 
   * @param attrName The attribute name.
   * @param attrIsRequired The attribute type value.
   * @param attrComplexValue The attribute's value.
   * @param attrStatus The attribute's status value.
   */
  public PersonalAttribute(final String attrName, final boolean attrIsRequired,
    final List<String> attrComplexValue, final String attrStatus) {
    this.setName(attrName);
    this.setIsRequired(attrIsRequired);
    this.setValue(attrComplexValue);
    this.setStatus(attrStatus);
  }
  
  /**
   * PersonalAttribute Constructor for complex values.
   * 
   * @param attrName The attribute name.
   * @param attrIsRequired The attribute type value.
   * @param attrComplexValue The attribute's complex value.
   * @param attrStatus The attribute's status value.
   */
  public PersonalAttribute(final String attrName, final boolean attrIsRequired,
    final Map<String, String> attrComplexValue, final String attrStatus) {
    this.setName(attrName);
    this.setIsRequired(attrIsRequired);
    this.setComplexValue(attrComplexValue);
    this.setStatus(attrStatus);
  }
  
  /**
   * {@inheritDoc}
   */
  @SuppressWarnings("unchecked")
  public Object clone() {
    
    try {
      final PersonalAttribute personalAttr = (PersonalAttribute) super.clone();
      personalAttr.setIsRequired(this.isRequired());
      personalAttr.setName(this.getName());
      personalAttr.setStatus(this.getStatus());
        personalAttr.eidasLegalPersonAttr=this.eidasLegalPersonAttr;
        personalAttr.eidasNaturalPersonAttr=this.eidasNaturalPersonAttr;
      if (!isEmptyValue()) {
        final List<String> val =
          (List<String>) ((ArrayList<String>) this.getValue()).clone();
        personalAttr.setValue(val);
      }
      if (!isEmptyComplexValue()) {
        final Map<String, String> complexVal =
          (Map<String, String>) ((HashMap<String, String>) this
            .getComplexValue()).clone();
        personalAttr.setComplexValue(complexVal);
      }
      return personalAttr;
    } catch (final CloneNotSupportedException e) {
      LOG.trace("Nothing to do.");
      throw new InternalErrorEIDASException(
        EIDASUtil.getConfig(EIDASErrors.INTERNAL_ERROR.errorCode()),
        EIDASUtil.getConfig(EIDASErrors.INTERNAL_ERROR.errorMessage()), e);
    }
  }
  
  /**
   * Getter for the required value.
   * 
   * @return The required value.
   */
  public boolean isRequired() {
    return required;
  }
  
  /**
   * Setter for the required value.
   * 
   * @param attrIsRequired this attribute?
   */
  public void setIsRequired(final boolean attrIsRequired) {
    this.required = attrIsRequired;
  }
  
  /**
   * Getter for the name value.
   * 
   * @return The name value.
   */
  public String getName() {
    return name;
  }
  
  /**
   * Setter for the name value.
   * 
   * @param attrName The personal attribute name.
   */
  public void setName(final String attrName) {
    this.name = attrName;
  }
  
  /**
   * Getter for the value.
   * 
   * @return The list of values.
   */
  public List<String> getValue() {
    return value;
  }

  public String getDisplayValue() {
    if(value!=null && value.size()==1){
      return value.get(0);
    }else{
      return getValue().toString();
    }
  }

  /**
   * Setter for the list of values.
   * 
   * @param attrValue The personal attribute value.
   */
  public void setValue(final List<String> attrValue) {
    if (attrValue != null) {
      this.value = attrValue;
    }
  }
  
  /**
   * Getter for the status.
   * 
   * @return The status value.
   */
  public String getStatus() {
    return status;
  }
  
  /**
   * Setter for the status value.
   * 
   * @param attrStatus The personal attribute status.
   */
  public void setStatus(final String attrStatus) {
    this.status = attrStatus;
  }
  
  /**
   * Getter for the complex value.
   * 
   * @return The complex value.
   */
  public Map<String, String> getComplexValue() {
    return complexValue;
  }
  
  /**
   * Setter for the complex value.
   * 
   * @param complexVal The personal attribute Complex value.
   */
  public void setComplexValue(final Map<String, String> complexVal) {
    if (complexVal != null) {
      this.complexValue = complexVal;
    }
  }
  
  /**
   * Getter for the personal's friendly name.
   * 
   * @return The personal's friendly name value.
   */
  public String getFriendlyName() {
    return friendlyName;
  }
  
  /**
   * Setter for the personal's friendly name.
   * 
   * @param fName The personal's friendly name.
   */
  public void setFriendlyName(final String fName) {
    this.friendlyName = fName;
  }
  
  /**
   * Return true the value is empty.
   * 
   * @return True if the value is empty "[]";
   */
  public boolean isEmptyValue() {
    return value==null || value.isEmpty() || (value.size() == 1 && value.get(0).length() == 0);
  }
  
  /**
   * Returns true if the Complex Value is empty.
   * 
   * @return True if the Complex Value is empty;
   */
  public boolean isEmptyComplexValue() {
    return complexValue.isEmpty();
  }
  
  /**
   * Returns true if the Status is empty.
   * 
   * @return True if the Status is empty;
   */
  public boolean isEmptyStatus() {
    return status == null || status.length() == 0;
  }

  public String getFullName() {
    return fullName;
  }

	  public void setFullName(String fullNameArg) {
	    this.fullName = fullNameArg;
	  }

	    public boolean isEidasNaturalPersonAttr() {
	        return eidasNaturalPersonAttr;
	    }

	    public void setEidasNaturalPersonAttr(boolean eidasNaturalPersonAttrArg) {
	        this.eidasNaturalPersonAttr = eidasNaturalPersonAttrArg;
	    }

	    public boolean isEidasLegalPersonAttr() {
	        return eidasLegalPersonAttr;
	    }

	    public void setEidasLegalPersonAttr(boolean eidasLegalPersonAttrArg) {
	        this.eidasLegalPersonAttr = eidasLegalPersonAttrArg;
	    }

    /**
   * Prints the PersonalAttribute in the following format.
   * name:required:[v,a,l,u,e,s]|[v=a,l=u,e=s]:status;
   * 
   * @return The PersonalAttribute as a string.
   */
  public String toString() {
    final StringBuilder strBuild = new StringBuilder();
    
    AttributeUtil.appendIfNotNull(strBuild, getName());
    strBuild.append(EIDASValues.ATTRIBUTE_TUPLE_SEP.toString());
    AttributeUtil.appendIfNotNull(strBuild, String.valueOf(isRequired()));
    strBuild.append(EIDASValues.ATTRIBUTE_TUPLE_SEP.toString());
    strBuild.append('[');
    
    if (isEmptyValue()) {
      if (!isEmptyComplexValue()) {
        AttributeUtil.appendIfNotNull(strBuild, AttributeUtil.mapToString(
          getComplexValue(), EIDASValues.ATTRIBUTE_VALUE_SEP.toString()));
      }
    } else {
      AttributeUtil.appendIfNotNull(
        strBuild,
        AttributeUtil.listToString(getValue(),
          EIDASValues.ATTRIBUTE_VALUE_SEP.toString()));
    }
    
    strBuild.append(']');
    strBuild.append(EIDASValues.ATTRIBUTE_TUPLE_SEP.toString());
    AttributeUtil.appendIfNotNull(strBuild, getStatus());
    strBuild.append(EIDASValues.ATTRIBUTE_SEP.toString());
    
    return strBuild.toString();
  }
  
}
