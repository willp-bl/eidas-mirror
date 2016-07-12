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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.EIDASSubStatusCode;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.auth.specific.ITranslatorService;

/**
 * This class is a service used by {@link AUSERVICE} to normalise attribute names
 * and values.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.5 $, $Date: 2010-11-18 23:17:50 $
 * 
 * @see ISERVICETranslatorService
 */
public final class AUSERVICETranslator implements ISERVICETranslatorService {
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AUSERVICETranslator.class
    .getName());
  
  /**
   * Specific interface.
   */
  private ITranslatorService specificNode;
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesToFormat(
    final IPersonalAttributeList pal) {
    return specificNode.normaliseAttributeNamesTo(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeValuesToFormat(
    final ISERVICESAMLService samlService, final EIDASAuthnRequest authData,
    final String ipUserAddress) {
    
    try {
      return specificNode.normaliseAttributeValuesTo(authData
        .getPersonalAttributeList());
    } catch (SecurityEIDASException e) {
      // We shouldn't check a RuntimeException, but the Specification says
      // that we MUST return to the Connector a SAML Error if we get an invalid value
      // for an attribute! Therefore, as we can't change the API, we have to
      // handle it.
      final byte[] error =
        samlService
          .generateErrorAuthenticationResponse(authData, EIDASUtil
            .getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
            EIDASSubStatusCode.INVALID_ATTR_NAME_VALUE_URI.toString(), EIDASUtil
              .getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
            ipUserAddress, true);
      
      throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(error),
        EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
        EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
        e);
    }
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesFromFormat(
    final IPersonalAttributeList pal) {
    
    return specificNode.normaliseAttributeNamesFrom(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList deriveAttributesToFormat(
    final ISERVICESAMLService samlService, final IEIDASSession session,
    final EIDASAuthnRequest authData, final String ipUserAddress) {
    
    try {
      return specificNode.deriveAttributeTo(session,
        authData.getPersonalAttributeList());
    } catch (SecurityEIDASException e) {
      // We shouldn't check a RuntimeException, but the Specification says
      // that we MUST
      // return to Connector a SAML Error if we get an invalid value for an
      // attribute! Therefore,
      // as we can't change the API, we have to handle it.
      final byte[] error =
        samlService
          .generateErrorAuthenticationResponse(authData, EIDASUtil
            .getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
            EIDASSubStatusCode.INVALID_ATTR_NAME_VALUE_URI.toString(), EIDASUtil
              .getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
            ipUserAddress, true);
      
      throw new EIDASServiceException(EIDASUtil.encodeSAMLToken(error),
        EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
        EIDASUtil.getConfig(EIDASErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
        e);
      
    }
    
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList deriveAttributesFromFormat(
    final IPersonalAttributeList pal) {
    LOG.trace("Passing control to SpecificNode module");
    return specificNode.deriveAttributeFrom(pal);
  }
  
  /**
   * Getter for specificNode.
   * 
   * @return The specificNode value.
   * 
   * @see ITranslatorService
   */
  public ITranslatorService getSpecificNode() {
    return specificNode;
  }
  
  /**
   * Setter for specificNode.
   * 
   * @param specificNode The new specificNode value.
   * 
   * @see ITranslatorService
   */
  public void setSpecificNode(final ITranslatorService specificNode) {
    this.specificNode = specificNode;
  }
  
}
