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

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.specific.ITranslatorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is a service used by {@link AUSPEPS} to normalise attribute names
 * and values.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.4 $, $Date: 2010-11-18 23:17:50 $
 * 
 * @see ISPEPSTranslatorService
 */
public final class AUSPEPSTranslator implements ISPEPSTranslatorService {
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AUSPEPSTranslator.class
    .getName());
  
  /**
   * Specific interface.
   */
  private ITranslatorService specPeps;
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesToStork(
    final IPersonalAttributeList pal) {
    
    LOG.trace("Control Attribute Name to Specific PEPS");
    return specPeps.normaliseAttributeNamesToStork(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeValuesToStork(
    final IPersonalAttributeList pal) {
    
    LOG.trace("Control Attribute value to Specific PEPS");
    return specPeps.normaliseAttributeValuesToStork(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesFromStork(
    final IPersonalAttributeList pal) {
    
    LOG.trace("Control normalize attribute names to Specific PEPS");
    return specPeps.normaliseAttributeNamesFromStork(pal);
  }
  
  /**
   * Getter for specPeps.
   * 
   * @return The specPeps value.
   */
  public ITranslatorService getSpecPeps() {
    return specPeps;
  }
  
  /**
   * Setter for specPeps.
   * 
   * @param nSpecPeps The new specPeps value.
   */
  public void setSpecPeps(final ITranslatorService nSpecPeps) {
    this.specPeps = nSpecPeps;
  }
  
}
