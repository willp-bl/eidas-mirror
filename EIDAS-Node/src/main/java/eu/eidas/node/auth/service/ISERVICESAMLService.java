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
package eu.eidas.node.auth.service;

import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;

/**
 * Interface for communicating with the SAMLEngine.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.29 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ISERVICESAMLService {
  
  /**
   * Decodes the incoming SAML Token from {@link Base64}.
   * 
   * @param samlToken The Token to be decoded.
   * 
   * @return A byte array containing the decoded SAML Token.
   */
  byte[] getSAMLToken(String samlToken);
  
  /**
   * Validates the SAML Token request.
   * 
   * @param samlObj the SAML Token to be validated.
   * @param session The current session.
   * @param ipUserAddress The citizen's IP address.
   * 
   * @return The processed authentication request.
   * 
   * @see EIDASAuthnRequest
   * @see IEIDASSession
   */
  EIDASAuthnRequest processAuthenticationRequest(byte[] samlObj,
    IEIDASSession session, String ipUserAddress);
  
  /**
   * Generates a SAML response Token.
   * 
   * @param authData The authentication request.
   * @param ipUserAddress The citizen's IP address.
   * @param isConsent Is a Citizen's consent page?
   *
   * 
   * @return A byte array containing the SAML Response Token.
   * 
   * @see EIDASAuthnRequest
   */
  byte[] generateAuthenticationResponse(EIDASAuthnRequest authData,
    String ipUserAddress, boolean isConsent);
  
  /**
   * Constructs a SAML response token in case of error.
   * 
   * @param authData The authentication request.
   * @param errorCode The status code.
   * @param subCode The sub status code.
   * @param errorMessage The error message.
   * @param ipUserAddress The citizen's IP address.
   * @param isAuditable Is a auditable saml error?
   * 
   * @return A byte array containing the SAML Response.
   * 
   * @see EIDASAuthnRequest
   */
  byte[] generateErrorAuthenticationResponse(EIDASAuthnRequest authData,
    String errorCode, String subCode, String errorMessage,
    String ipUserAddress, boolean isAuditable);
  
  /**
   * Checks if all mandatory attributes have the status to Available.
   * 
   * @param authData The authentication request.
   * @param ipUserAddr The citizen's IP address.
   * 
   * @see EIDASAuthnRequest
   */
  void checkMandatoryAttributes(EIDASAuthnRequest authData, String ipUserAddr);
  
  /**
   * Validates the values of the attributes.
   * 
   * @param authData The authentication request.
   * @param ipUserAddress The citizens' IP address.
   * 
   * @see EIDASAuthnRequest
   */
  void checkAttributeValues(EIDASAuthnRequest authData, String ipUserAddress);

  String getSamlEngineInstanceName();
  
  /**
   * Performs validation on the response received from IdP/AP
   * @param authData
   * @param session
   * @param ipUserAddr
   */
  void validateAPResponses(EIDASAuthnRequest authData, IEIDASSession session, String ipUserAddr);
}
