/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software distributed 
 * under the License is distributed on an "AS IS" BASIS,  WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the 
 * specific language governing permissions and    limitations under the License.
 */
package eu.stork.peps.specific.derivation;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.joda.time.DateTime;

import eu.stork.peps.auth.commons.DateUtil;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.specific.IDeriveAttribute;

/**
 * Class that implements the derivation of the Age attribute.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 * 
 */
public final class DeriveAge implements IDeriveAttribute {
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(DeriveAge.class.getName());
  
  /**
   * The date's pattern.
   */
  private String pattern;
  
  /**
   * The date of birth's separator.
   */
  private String specificSeparator;
  
  /**
   * If date of birth has a separator char.
   */
  private boolean hasSeparator;
  
  /**
   * {@inheritDoc} Derives the attribute age from the Date of Birth.
   */
  public void deriveAttributeToData(final PersonalAttribute pAttr,
    final IStorkSession session) {
    
    if (pAttr == null) {
      LOG.debug("[deriveAttributeToData] Personal Attribute List is null!");
      return;
    }
    
    final List<String> values = new ArrayList<String>();
    List<String> attrValue = pAttr.getValue();
    
    if (!attrValue.isEmpty() && pattern != null) {
      String birthdate = attrValue.get(0);
      
      if (isHasSeparator()) {
        birthdate =
          birthdate.replace(getSpecificSeparator(),
            PEPSValues.EMPTY_STRING.toString());
      }
      if (birthdate.length() == 8) {
        final DateTime now = new DateTime();
        final int age = DateUtil.calculateAge(birthdate, now, pattern);
        
        values.add(Integer.toString(age));
      }
    }
    pAttr.setValue(values);
  }
  
  /**
   * Setter for pattern.
   * 
   * @param pattern The pattern to set.
   */
  public void setPattern(final String pattern) {
    this.pattern = pattern;
  }
  
  /**
   * Getter for pattern.
   * 
   * @return The pattern value.
   */
  public String getPattern() {
    return pattern;
  }
  
  /**
   * Setter for specificSeparator.
   * 
   * @param specificSeparator The specificSeparator char.
   */
  public void setSpecificSeparator(final String specificSeparator) {
    this.specificSeparator = specificSeparator;
  }
  
  /**
   * Getter for specificSeparator.
   * 
   * @return The specificSeparator char.
   */
  public String getSpecificSeparator() {
    return specificSeparator;
  }
  
  /**
   * Setter for hasSeparator.
   * 
   * @param hasSeparator If the date of birth has a separator char.
   */
  public void setHasSeparator(final boolean hasSeparator) {
    this.hasSeparator = hasSeparator;
  }
  
  /**
   * Getter for hasSeparator.
   * 
   * @return The hasSeparator value.
   */
  public boolean isHasSeparator() {
    return hasSeparator;
  }
  
}
