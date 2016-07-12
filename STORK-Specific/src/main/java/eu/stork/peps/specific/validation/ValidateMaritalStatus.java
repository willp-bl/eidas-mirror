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
package eu.stork.peps.specific.validation;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.stork.peps.auth.specific.ICheckAttributeValue;
import eu.stork.peps.auth.specific.SpecificPEPS;

/**
 * Class that implements the validation of the marital status attribute.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 * 
 */
public final class ValidateMaritalStatus implements ICheckAttributeValue {
   
   /**
    * Logger object.
    */
   private static final Logger LOG = LoggerFactory.getLogger(SpecificPEPS.class
      .getName());
   
   /**
    * {@inheritDoc} Checks if the value is one of the following: 'S', 'M', 'P',
    * 'D', 'W'
    */
   public boolean checkValue(final List<String> values,
      final String expectedValue) {

      boolean retVal = false;
      
      final String value = values.get(0);
      if (value != null && value.length() == 1 && expectedValue.contains(value)) {
         retVal = true;
      }
      
      LOG.trace("[checkValue] " + retVal);
      return retVal;
   }
   
}
