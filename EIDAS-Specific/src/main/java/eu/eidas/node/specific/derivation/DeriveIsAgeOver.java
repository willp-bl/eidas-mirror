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
package eu.eidas.node.specific.derivation;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.joda.time.DateTime;

import eu.eidas.auth.commons.DateUtil;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.specific.IDeriveAttribute;

/**
 * Class that implements the derivation of the IsAgeOver attribute.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 * 
 */
public final class DeriveIsAgeOver implements IDeriveAttribute {
   
   /**
    * Logger object.
    */
   private static final Logger LOG = LoggerFactory.getLogger(DeriveIsAgeOver.class.getName());
   
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
    * {@inheritDoc} Derives the attribute is age over from the Date of Birth.
    */
   public void deriveAttributeToData(final PersonalAttribute pAttr,
      final IEIDASSession session) {

      final List<String> attrVal = (ArrayList<String>) pAttr.getValue();
      List<String> values = new ArrayList<String>();
      
      final String derivedName = pAttr.getName();
      final List<String> minAges =
         ((EIDASAuthnRequest) session.get(EIDASParameters.AUTH_REQUEST.toString()))
            .getPersonalAttributeList().get(derivedName).getValue();
      
      if (!attrVal.isEmpty() && pattern != null && isAgeValid(minAges)) {
         String birthdate = attrVal.get(0);
         LOG.debug("[deriveAttributeToData] attr name: " + derivedName);
         if (isHasSeparator()) {
            birthdate =
               birthdate.replace(
                  getSpecificSeparator(),
                  EIDASValues.EMPTY_STRING.toString());
         }
         if (birthdate.length() == 8) {
            final DateTime now = new DateTime();
            final int age = DateUtil.calculateAge(birthdate, now, pattern);
            
            final int minAge = Integer.parseInt(minAges.get(0), 10);
            
            if (age >= minAge) {
               values = minAges;
            }
         }
      }
      pAttr.setValue(values);
   }
   
   /**
    * Checks if the value provided is numeric.
    * 
    * @param minAges List containing a value.
    * @return True if the value is numeric, false otherwise.
    */
   private boolean isAgeValid(final List<String> minAges) {
      if (minAges.size() == 1 && minAges.get(0) != null) {
         return StringUtils.isNumeric(minAges.get(0));
      }
      
      return false;
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
