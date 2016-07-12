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

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASAuthnRequest;

/**
 * Interface for normalizing the {@link IPersonalAttributeList}.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.23 $, $Date: 2010-11-18 23:17:50 $
 */
public interface ISERVICETranslatorService {
  
  /**
   * Normalizes the attributes' name from a given {@link IPersonalAttributeList}
   * to a common format.
   * 
   * @param pal The personal attribute list to normalize.
   * 
   * @return The normalized personal attribute list.
   * 
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList normaliseAttributeNamesToFormat(
    IPersonalAttributeList pal);
  
  /**
   * Normalizes the attributes' name from a given {@link IPersonalAttributeList}
   * to a specific format.
   * 
   * @param pal The personal attribute list to normalize.
   * 
   * @return The normalized personal attribute list.
   * 
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList normaliseAttributeNamesFromFormat(
    IPersonalAttributeList pal);
  
  /**
   * Normalizes the attributes' values from a given
   * {@link IPersonalAttributeList} to the common format.
   * 
   * @param samlService The SAML Service.
   * @param authData The authentication request.
   * @param ipUserAddress The citizen's IP address.
   * 
   * @return The normalized personal attribute list's values.
   * 
   * @see ISERVICESAMLService
   * @see EIDASAuthnRequest
   */
  IPersonalAttributeList normaliseAttributeValuesToFormat(
    ISERVICESAMLService samlService, EIDASAuthnRequest authData,
    String ipUserAddress);
  
  /**
   * Derives the attributes' name to a common format. Updates the original
   * Personal Attribute List, stored in the session, based on the values of
   * attrList.
   * 
   * @param samlService The SAML Service.
   * @param session The session containing the original attribute list to
   *          update.
   * @param authData The authentication request.
   * @param ipUserAddress The citizen's IP address.
   * 
   * @return The new personal attribute list with the derived attributes.
   * 
   * @see ISERVICESAMLService
   * @see IEIDASSession
   */
  IPersonalAttributeList deriveAttributesToFormat(ISERVICESAMLService samlService,
    IEIDASSession session, EIDASAuthnRequest authData, String ipUserAddress);
  
  /**
   * Derives the attributes' name to a specific format.
   * 
   * @param pal Personal attribute list with the attributes to derive.
   * 
   * @return The new personal attribute list with the derived attributes.
   * 
   * @see IPersonalAttributeList
   */
  IPersonalAttributeList deriveAttributesFromFormat(IPersonalAttributeList pal);
}
