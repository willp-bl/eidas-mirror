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

import eu.stork.peps.auth.commons.CitizenConsent;
import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.commons.STORKAuthnRequest;

/**
 * Interface that supplies methods for processing citizen-related matters.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.28 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ICPEPSCitizenService {
  
  /**
   * Checks if the citizen consent has all the required mandatory attributes.
   * 
   * @param consent The citizen supplied consent.
   * @param authData The authentication request.
   * @param ipUserAddress The citizen's IP address.
   * @param cpepsSAMLService The C-PEPS Saml Service.
   * 
   * @see CitizenConsent
   * @see STORKAuthnRequest
   * @see ICPEPSSAMLService
   */
  void processCitizenConsent(CitizenConsent consent,
    STORKAuthnRequest authData, String ipUserAddress,
    ICPEPSSAMLService cpepsSAMLService);
  
  /**
   * Constructs the Citizen Consent based on the checked boxes from consent-type
   * form.
   * 
   * @param parameters A map of the selected attributes.
   * @param personalList The personal attribute list.
   * 
   * @return CitizenConsent containing the mandatory and optional attributes
   *         that PEPS has permission to request.
   * 
   * @see CitizenConsent
   * @see Map
   * @see IPersonalAttributeList
   */
  CitizenConsent getCitizenConsent(Map<String, String> parameters,
    IPersonalAttributeList personalList);
  
  /**
   * Eliminates attributes without consent, and updates the Personal Attribute
   * List.
   * 
   * @param citizenConsent The attributes the citizen gives permission to be
   *          accessed.
   * @param personalList The list to update.
   * 
   * @return The updated Personal Attribute List.
   * 
   * @see CitizenConsent
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList updateAttributeList(CitizenConsent citizenConsent,
    IPersonalAttributeList personalList);
  
  /**
   * Replaces the attribute list in session with the one provided.
   * 
   * @param session The current session.
   * @param attributeList The attribute list.
   * 
   * @return The updated Personal Attribute List.
   * 
   * @see IStorkSession
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList updateAttributeList(IStorkSession session,
    IPersonalAttributeList attributeList);
  
  /**
   * Updates the values and the status of the attributeList in session.
   * 
   * @param session The current session.
   * @param attributeList The updated personal attribute list.
   * 
   * @return The updated Personal Attribute List.
   * 
   * @see IStorkSession
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList updateAttributeListValues(IStorkSession session,
    IPersonalAttributeList attributeList);
  
}
