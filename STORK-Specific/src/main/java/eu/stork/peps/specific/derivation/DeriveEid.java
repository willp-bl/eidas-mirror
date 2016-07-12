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

import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.specific.IDeriveAttribute;

/**
 * Class that implements the derivation of the eIdentifier attribute.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 * 
 */
public final class DeriveEid implements IDeriveAttribute {
   
   /**
    * Destination country.
    */
   private String destCountry;
   
   /**
    * {@inheritDoc} Creates the eId from the country of origin, country of
    * destination, and the Id retrieved from the IdP/AP.
    */
   public void deriveAttributeToData(final PersonalAttribute pAttr,
      final IStorkSession session) {

      final List<String> values = (ArrayList<String>) pAttr.getValue();
      
      final String countryOrigin =
         ((STORKAuthnRequest) session.get(PEPSParameters.AUTH_REQUEST
            .toString())).getCountry();
      
      if (isPersonalAttributeCorrect(values) && destCountry != null && countryOrigin != null) {
         final String eId = values.get(0);
         
         values.remove(0);
         values.add(destCountry
            + PEPSValues.EID_SEPARATOR.toString() + countryOrigin
            + PEPSValues.EID_SEPARATOR.toString() + eId);
      }
      
      pAttr.setValue(values);
   }

   private boolean isPersonalAttributeCorrect(List<String> values){
       return values != null && values.size() == 1 && values.get(0) != null;
   }
   
   /**
    * Setter for destCountry.
    * 
    * @param destCountry The destCountry to set.
    */
   public void setDestCountry(final String destCountry) {
      this.destCountry = destCountry;
   }
   
   /**
    * Getter for destCountry.
    * 
    * @return The destCountry value.
    */
   public String getDestCountry() {
      return destCountry;
   }
   
}
