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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.specific.ITranslatorService;
import eu.eidas.node.auth.specific.SpecificEidasNode;

/**
 * This class is a service used by {@link AUCONNECTOR} to normalise attribute names
 * and values.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.4 $, $Date: 2010-11-18 23:17:50 $
 * 
 * @see ICONNECTORTranslatorService
 */
public final class AUCONNECTORTranslator implements ICONNECTORTranslatorService {
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AUCONNECTORTranslator.class
    .getName());
  
  /**
   * Specific interface.
   */
  private ITranslatorService specNode;
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesToFormat(
    final IPersonalAttributeList pal) {
    
    LOG.trace("Control Attribute Name to Specific EidasNode");
    return specNode.normaliseAttributeNamesTo(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeValuesToFormat(
    final IPersonalAttributeList pal) {
    
    LOG.trace("Control Attribute value to Specific EidasNode");
    return specNode.normaliseAttributeValuesTo(pal);
  }
  
  /**
   * {@inheritDoc}
   */
  public IPersonalAttributeList normaliseAttributeNamesFromFormat(
    final IPersonalAttributeList pal) {
    
    LOG.trace("Control normalize attribute names to Specific EidasNode");
    return specNode.normaliseAttributeNamesFrom(pal);
  }
  
  /**
   * Getter for specNode.
   * 
   * @return The specNode value.
   */
  public ITranslatorService getSpecNode() {
    return specNode;
  }
  
  /**
   * Setter for specNode.
   * 
   * @param nSpecNode The new specNode value.
   */
  public void setSpecNode(final ITranslatorService nSpecNode) {
    this.specNode = nSpecNode;
  }
  
}
