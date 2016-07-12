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
package eu.stork.peps.auth.speps;

import java.util.List;
import java.util.Map;

import eu.stork.peps.auth.commons.Country;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.STORKAuthnRequest;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Interface for managing incoming requests.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.21 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ISPEPSService {
  
  /**
   * Generates a SAML token for the Country Selector.
   * 
   * @param parameters A map of parameters.
   * 
   * @return The SAML token in the format of byte array.
   * 
   * @see Map
   */
  byte[] processCountrySelector(Map<String, String> parameters);
  
  /**
   * Generates the Country Selector List.
   * 
   * @return The List of known countries.
   * 
   * @see List
   */
  List<Country> getCountrySelectorList();
  
  /**
   * Validates the origin of the request and of the Country Selected, and
   * creates a SAML token to send to the C-PEPS.
   * 
   * @param parameters A map of parameters.
   * @param session The current session.
   * 
   * @return An authentication request.
   * 
   * @see STORKAuthnRequest
   * @see Map
   * @see IStorkSession
   */
  STORKAuthnRequest getAuthenticationRequest(Map<String, String> parameters,
    IStorkSession session);
  
  /**
   * Receives an Authentication Response, validates the origin of the response,
   * and generates a SAML token to be sent to the SP.
   * 
   * @param parameters A map of parameters.
   * @param session The current session.
   * 
   * @return An Authentication response.
   * 
   * @see STORKAuthnRequest
   * @see Map
   * @see IStorkSession
   */
  STORKAuthnRequest getAuthenticationResponse(Map<String, String> parameters,
    IStorkSession session);

  /**
   *
   * @param request
   * @return true when the response is to be processed by a decentralized plugin
   */
  boolean isPluginResponse(HttpServletRequest request);

  /**
   *
   * @param request
   * @return the response from the decentralized plugin
   * When null, the plugin itself performed a redirection
   */
  String processPluginResponse(final HttpServletRequest request, final HttpServletResponse response, final ServletContext context, final IStorkSession storkSession, final Map<String, String> parameters);
}
