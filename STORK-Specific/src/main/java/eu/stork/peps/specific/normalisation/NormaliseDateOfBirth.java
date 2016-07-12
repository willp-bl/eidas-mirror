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
package eu.stork.peps.specific.normalisation;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.auth.commons.DateUtil;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.commons.exceptions.SecurityPEPSException;
import eu.stork.peps.auth.specific.INormaliseValue;

/**
 * Implementation of Date of Birth's normalization.
 * 
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 * 
 */
public final class NormaliseDateOfBirth implements INormaliseValue {
   
   /**
    * Logger object.
    */
   private static final Logger LOG = LoggerFactory.getLogger(NormaliseDateOfBirth.class.getName());
   
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
    * {@inheritDoc} Normalizes the attribute Date of Birth accordingly to the
    * set of rules specified in the file 'specific.properties'.
    */
   public void
      normaliseAttributeValueToStork(final PersonalAttribute personalAttribute) {

      final List<String> values =
         (ArrayList<String>) personalAttribute.getValue();
      
      if (values != null && values.size() == 1 && values.get(0) != null) {
         
         String birthdate = values.get(0);
         
         if (hasSeparator) {
            birthdate =
               birthdate.replace(specificSeparator, PEPSValues.EMPTY_STRING
                  .toString());
         }
         
         if (!DateUtil.isValidFormatDate(birthdate, pattern)) {
            LOG.info("ERROR : [normaliseAttributeValueToStork] Invalid Format Date. Invalid Personal Attribute ("
                    + personalAttribute.getName() + ")");
            throw new SecurityPEPSException(
               PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE
                  .errorCode()),
               PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE
                  .errorMessage(personalAttribute.getName())));
         }
         
         values.clear();
         values.add(birthdate);
         personalAttribute.setValue(values);

      } else {
         LOG.info("ERROR : [normaliseAttributeValueToStork] Couldn't normalise date value. Invalid Personal Attribute ("
                 + personalAttribute.getName() + ")");
         throw new SecurityPEPSException(
            PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
            PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE
               .errorMessage(personalAttribute.getName())));
      }
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
   public boolean getHasSeparator() {
      return hasSeparator;
   }
   
   /**
    * Setter for specificSeparator.
    * 
    * @param specificSeparator The separator char of date of birth.
    */
   public void setSpecificSeparator(final String specificSeparator) {
      this.specificSeparator = specificSeparator;
   }
   
   /**
    * Getter for specificSeparator.
    * 
    * @return The separator char of date of birth.
    */
   public String getSpecificSeparator() {
      return specificSeparator;
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
   
}
