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
package eu.eidas.node.auth.connector;

import java.util.List;
import java.util.Map;

import eu.eidas.auth.commons.Country;
import eu.eidas.auth.commons.EIDASAuthnRequest;

/**
 * Interface to that holds the method to present the citizen the country
 * selector form.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.12 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ICONNECTORCountrySelectorService {
  
  /**
   * Creates the CountrySelector form.
   * 
   * @return List of known countries and respective IDs.
   * 
   * @see List
   */
  List<Country> createCountrySelector();
  
  /**
   * Creates authentication data and checks if a SP is allowed to access
   * requested attributes.
   * 
   * @param parameters A map of parameters needed by the method.
   * @param connectorSAMLService The Eidas Connector Service.
   * @return An authentication request.
   * 
   * @see EIDASAuthnRequest
   * @see Map
   */
  EIDASAuthnRequest checkCountrySelectorRequest(Map<String, String> parameters,
    ICONNECTORSAMLService connectorSAMLService);
}
