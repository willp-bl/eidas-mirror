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
package eu.stork.peps.auth.cpeps;

import java.util.Map;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.STORKAuthnRequest;

/**
 * Interface for handling incoming requests.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.29 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ICPEPSService {
  
  /**
   * Decodes the SAML Token, normalizes data from STORK format to specific
   * format, and presents a consent-type form for the citizen to choose the
   * optional attributes to be requested from the IdP/AP. Alternatively, the
   * user can cancel the process.
   * 
   * @param parameters A map of attributes.
   * @param session The session to store the incoming authentication request.
   * 
   * @return The newly created authentication request.
   * 
   * @see STORKAuthnRequest
   * @see Map
   * @see IStorkSession
   */
  STORKAuthnRequest processAuthenticationRequest(
    Map<String, String> parameters, IStorkSession session);
  
  /**
   * Validates the consent sent by the citizen, then redirects the citizen to
   * the IdP for the login process.
   * 
   * @param parameters A map of attributes.
   * @param session The current session.
   * @param askConsentType Whether The consent-type form was present or not.
   * 
   * @return The Personal Attribute List updated with user consent.
   * 
   * @see Map
   * @see IStorkSession
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList processCitizenConsent(Map<String, String> parameters,
    IStorkSession session, boolean askConsentType);
  
  /**
   * Processes the incoming response from the IdP and updates the personal
   * attribute list, in session, if the IdP provided any attributes' value.
   * 
   * @param params A map of attributes.
   * @param session The current session.
   * 
   * @see Map
   * @see IStorkSession
   */
  void processIdPResponse(Map<String, String> params, IStorkSession session);
  
  /**
   * Normalizes the attributes to STORK format, generates the SAML Tokens to
   * send to S-PEPS, and if required displays the consent-value form.
   * 
   * @param parameters A map of attributes.
   * @param session The current session.
   * 
   * @return The new authentication request.
   * 
   * @see STORKAuthnRequest
   * @see Map
   * @see IStorkSession
   */
  STORKAuthnRequest processAPResponse(Map<String, String> parameters,
    IStorkSession session);
  
  /**
   * Generates an error SAML token.
   * 
   * @param authData The authentication request.
   * @param errorId The status code to set.
   * @param ipUserAddress The citizen's IP address.
   * 
   * @return A {@link Base64} encoded SAML token.
   * 
   * @see STORKAuthnRequest
   * @see PEPSErrors
   * @see Base64
   */
  String generateSamlTokenFail(STORKAuthnRequest authData, PEPSErrors errorId,
    String ipUserAddress);
  
}
