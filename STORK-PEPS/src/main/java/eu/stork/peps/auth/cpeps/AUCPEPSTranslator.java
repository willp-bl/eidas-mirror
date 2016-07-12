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

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.CPEPSException;
import eu.stork.peps.auth.commons.exceptions.SecurityPEPSException;
import eu.stork.peps.auth.specific.ITranslatorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is a service used by {@link AUCPEPS} to normalise attribute names
 * and values.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.5 $, $Date: 2010-11-18 23:17:50 $
 * 
 * @see ICPEPSTranslatorService
 */
public final class AUCPEPSTranslator implements ICPEPSTranslatorService {
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AUCPEPSTranslator.class
    .getName());
  
  /**
   * Specific interface.
   */
  private ITranslatorService specificPeps;
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesToStork(
    final IPersonalAttributeList pal) {
    return specificPeps.normaliseAttributeNamesToStork(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeValuesToStork(
    final ICPEPSSAMLService samlService, final STORKAuthnRequest authData,
    final String ipUserAddress) {
    
    try {
      return specificPeps.normaliseAttributeValuesToStork(authData
        .getPersonalAttributeList());
    } catch (SecurityPEPSException e) {
      // We shouldn't check a RuntimeException, but the Specification says
      // that we MUST return to S-PEPS a SAML Error if we get an invalid value
      // for an attribute! Therefore, as we can't change the API, we have to
      // handle it.
      final byte[] error =
        samlService
          .generateErrorAuthenticationResponse(authData, PEPSUtil
            .getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
            STORKSubStatusCode.INVALID_ATTR_NAME_VALUE_URI.toString(), PEPSUtil
              .getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
            ipUserAddress, true);
      
      throw new CPEPSException(PEPSUtil.encodeSAMLToken(error),
        PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
        PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
        e);
    }
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesFromStork(
    final IPersonalAttributeList pal) {
    
    return specificPeps.normaliseAttributeNamesFromStork(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList deriveAttributesToStork(
    final ICPEPSSAMLService samlService, final IStorkSession session,
    final STORKAuthnRequest authData, final String ipUserAddress) {
    
    try {
      return specificPeps.deriveAttributeToStork(session,
        authData.getPersonalAttributeList());
    } catch (SecurityPEPSException e) {
      // We shouldn't check a RuntimeException, but the Specification says
      // that we MUST
      // return to S-PEPS a SAML Error if we get an invalid value for an
      // attribute! Therefore,
      // as we can't change the API, we have to handle it.
      final byte[] error =
        samlService
          .generateErrorAuthenticationResponse(authData, PEPSUtil
            .getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
            STORKSubStatusCode.INVALID_ATTR_NAME_VALUE_URI.toString(), PEPSUtil
              .getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
            ipUserAddress, true);
      
      throw new CPEPSException(PEPSUtil.encodeSAMLToken(error),
        PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorCode()),
        PEPSUtil.getConfig(PEPSErrors.INVALID_ATTRIBUTE_VALUE.errorMessage()),
        e);
      
    }
    
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList deriveAttributesFromStork(
    final IPersonalAttributeList pal) {
    LOG.trace("Passing control to Specific PEPS");
    return specificPeps.deriveAttributeFromStork(pal);
  }
  
  /**
   * Getter for specificPeps.
   * 
   * @return The specificPeps value.
   * 
   * @see ITranslatorService
   */
  public ITranslatorService getSpecificPeps() {
    return specificPeps;
  }
  
  /**
   * Setter for specificPeps.
   * 
   * @param nSpecificPeps The new specificPeps value.
   * 
   * @see ITranslatorService
   */
  public void setSpecificPeps(final ITranslatorService nSpecificPeps) {
    this.specificPeps = nSpecificPeps;
  }
  
}
