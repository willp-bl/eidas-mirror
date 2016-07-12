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
package eu.eidas.auth.specific;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASAuthnRequest;

/**
 * Interface for attributes normalization.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 */
public interface ITranslatorService {
  
  /**
   * Translates the attributes from local format to supported (eg eIDAS) format.
   * 
   * @param personalList The Personal Attribute List.
   * 
   * @return The Personal Attribute List with normalised attributes.
   * 
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList normaliseAttributeNamesTo(
    IPersonalAttributeList personalList);
  
  /**
   * Translates the attributes values from local format to supported (eg eIDAS) format.
   * 
   * @param personalList The Personal Attribute List.
   * 
   * @return The PersonalAttributeList with normalised values.
   * 
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList normaliseAttributeValuesTo(
    IPersonalAttributeList personalList);
  
  /**
   * Translates the attributes from supprted format to local format.
   * 
   * @param personalList The Personal Attribute List.
   * 
   * @return The PersonalAttributeList with normalised attributes.
   * 
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList normaliseAttributeNamesFrom(
    IPersonalAttributeList personalList);
  
  /**
   * Derive Attribute Names To supported (eg eIDAS) format.
   * 
   * @param personalList The Personal Attribute List,
   * 
   * @return The PersonalAttributeList with derived attributes.
   * 
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList deriveAttributeFrom(
    IPersonalAttributeList personalList);
  
  /**
   * Derive Attribute Names from supported format.
   * 
   * @param session The session object.
   * @param modifiedList The Personal Attribute List.
   * 
   * @return The PersonalAttributeList with derived attributes.
   * 
   * @see IEIDASSession
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList deriveAttributeTo(IEIDASSession session,
    IPersonalAttributeList modifiedList);
  
  /**
   * Validate the values of the attributes.
   * 
   * @param authData The SAML's EIDASAuthnRequest object.
   * 
   * @return True, if all the attributes have values. False, otherwise.
   * 
   * @see EIDASAuthnRequest
   */
  boolean checkAttributeValues(EIDASAuthnRequest authData);
}
