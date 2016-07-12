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

import eu.eidas.auth.commons.*;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;

import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class is used by {@link AUCONNECTOR} to create the Country Selector and to
 * check the selected Country.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.7 $, $Date: 2011-02-18 07:04:16 $
 * 
 * @see ICONNECTORCountrySelectorService
 */
public final class AUCONNECTORCountrySelector implements
  ICONNECTORCountrySelectorService {
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AUCONNECTORCountrySelector.class.getName());
  
  /**
   * Connector authentication URL.
   */
  private String destination;
  
  /**
   * Connector's Util class.
   */
  private AUCONNECTORUtil connectorUtil;
  
  /**
   * {@inheritDoc}
   */
  public List<Country> createCountrySelector() {
    
    LOG.trace("Loading number of ServiceProxies");
    final int nService =
      Integer.parseInt(connectorUtil.loadConfig(EIDASParameters.EIDAS_NUMBER
        .toString()));
    LOG.debug("Number of ServiceProxies: " + nService);
    
    final List<Country> countries = new ArrayList<Country>(nService);
    
    for (int i = 1; i <= nService; i++) {
      
      final String countryId = connectorUtil.loadConfig(EIDASValues.EIDAS_SERVICE_PREFIX.index(i));
      final String countryName = connectorUtil.loadConfig(EIDASValues.EIDAS_SERVICE_PREFIX.name(i));
      if (StringUtils.isNotEmpty(countryId) && StringUtils.isNotEmpty(countryName)) {
      
        final Country countryInfo =
          new Country(countryId, countryName);
        
        LOG.trace("Index [" + i + "] has " + countryInfo.getCountryId()
          + "[ServiceProxy ID] and " + countryInfo.getCountryName() + " [ServiceProxy NAME].");
        countries.add(countryInfo);
      }
    }
    return countries;
  }
  
  /**
   * {@inheritDoc}
   */
  public EIDASAuthnRequest checkCountrySelectorRequest(
    final Map<String, String> parameters,
    final ICONNECTORSAMLService connectorSAMLService) {
    
    final String attrList =
      parameters.get(EIDASParameters.ATTRIBUTE_LIST.toString());
    
    final String qaa = parameters.get(EIDASParameters.SP_QAALEVEL.toString());
    
    final String spId = parameters.get(EIDASParameters.SP_ID.toString());
    
    // backwards compatibility
    final String providerName =
      parameters.get(EIDASParameters.PROVIDER_NAME_VALUE.toString());
    
    LOG.trace("Checking if SP is reliable");
    
    final IPersonalAttributeList pal = new PersonalAttributeList();
    pal.populate(attrList);
    
    // Validate if SP is trustworthy
    if (!connectorUtil.validateSP(parameters)) {
      throw new InvalidParameterEIDASException(
        EIDASUtil.getConfig(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID
          .errorCode()),
        EIDASUtil.getConfig(EIDASErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID
          .errorMessage()));
    }
    
    // check if SP is allowed to access requested attribute
    if (!connectorUtil.checkContents(spId, pal)) {
      LOG.info("BUSINESS EXCEPTION : SP can't request this attrs");
      throw new InvalidParameterEIDASException(
        EIDASUtil.getConfig(EIDASErrors.SP_COUNTRY_SELECTOR_SPNOTALLOWED
          .errorCode()),
        EIDASUtil.getConfig(EIDASErrors.SP_COUNTRY_SELECTOR_SPNOTALLOWED
          .errorMessage()));
    }
    
    LOG.trace("Saving authentication data.");
    
    final EIDASAuthnRequest authData = new EIDASAuthnRequest();
    authData.setPersonalAttributeList(pal);
    authData.setQaa(Integer.parseInt(qaa));
    authData.setMessageFormatName(SAMLExtensionFormat.STORK1_FORMAT_NAME);
    // backwards compatibility
    if (StringUtils.isNotEmpty(providerName)) {
      authData.setSPID(spId);
      authData.setProviderName(providerName);
    } else {
      authData.setProviderName(spId);
    }
    authData.setAssertionConsumerServiceURL(parameters
      .get(EIDASParameters.SP_URL.toString()));
    authData.setDestination(getDestination());
    authData.setSpApplication(parameters.get(EIDASParameters.SPAPPLICATION
      .toString()));
    authData.setSpCountry(parameters.get(EIDASParameters.SPCOUNTRY.toString()));
    authData.setSpInstitution(parameters.get(EIDASParameters.SPINSTITUTION
      .toString()));
    authData.setSpSector(parameters.get(EIDASParameters.SPSECTOR.toString()));
    if(parameters.containsKey(EIDASParameters.SP_METADATA_URL.toString())){
      authData.setIssuer(parameters.get(EIDASParameters.SP_METADATA_URL.toString()));
    }
    return authData;
  }


  /**
   * Setter for destination.
   * 
   * @param nDestination The destination to set.
   */
  public void setDestination(final String nDestination) {
    this.destination = nDestination;
  }
  
  /**
   * Getter for destination.
   * 
   * @return The destination value.
   */
  public String getDestination() {
    return destination;
  }
  
  /**
   * Setter for connectorUtil.
   * 
   * @param connectorUtil The connectorUtil to set.
   */
  public void setConnectorUtil(final AUCONNECTORUtil connectorUtil) {
    this.connectorUtil = connectorUtil;
  }
  
  /**
   * Getter for connectorUtil.
   * 
   * @return The connectorUtil value.
   */
  public AUCONNECTORUtil getConnectorUtil() {
    return connectorUtil;
  }
  
}
