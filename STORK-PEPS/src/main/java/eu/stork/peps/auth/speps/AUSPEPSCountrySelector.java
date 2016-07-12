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

import eu.stork.peps.auth.commons.*;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class is used by {@link AUSPEPS} to create the Country Selector and to
 * check the selected Country.
 * 
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.7 $, $Date: 2011-02-18 07:04:16 $
 * 
 * @see ISPEPSCountrySelectorService
 */
public final class AUSPEPSCountrySelector implements
  ISPEPSCountrySelectorService {
  
  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AUSPEPSCountrySelector.class.getName());
  
  /**
   * S-PEPS authentication URL.
   */
  private String destination;
  
  /**
   * S-PEPS's Util class.
   */
  private AUSPEPSUtil spepsUtil;
  
  /**
   * {@inheritDoc}
   */
  public List<Country> createCountrySelector() {
    
    LOG.trace("Loading number of C-PEPS");
    final int nPeps =
      Integer.parseInt(spepsUtil.loadConfig(PEPSParameters.PEPS_NUMBER
        .toString()));
    LOG.debug("Number of C-PEPS: " + nPeps);
    
    final List<Country> countries = new ArrayList<Country>(nPeps);
    
    for (int i = 1; i <= nPeps; i++) {
      
      final String countryId = spepsUtil.loadConfig(PEPSValues.CPEPS_PREFIX.index(i));
      final String countryName = spepsUtil.loadConfig(PEPSValues.CPEPS_PREFIX.name(i));
      if (StringUtils.isNotEmpty(countryId) && StringUtils.isNotEmpty(countryName)) {
      
        final Country pepInfo =
          new Country(countryId, countryName);
        
        LOG.trace("Index [" + i + "] has " + pepInfo.getCountryId()
          + "[PEPS ID] and " + pepInfo.getCountryName() + " [PEPS NAME].");
        countries.add(pepInfo);
      }
    }
    return countries;
  }
  
  /**
   * {@inheritDoc}
   */
  public STORKAuthnRequest checkCountrySelectorRequest(
    final Map<String, String> parameters,
    final ISPEPSSAMLService spepsSAMLService) {
    
    final String attrList =
      parameters.get(PEPSParameters.ATTRIBUTE_LIST.toString());
    
    final String qaa = parameters.get(PEPSParameters.SP_QAALEVEL.toString());
    
    final String spId = parameters.get(PEPSParameters.SP_ID.toString());
    
    // PEPS backwards compatibility
    final String providerName =
      parameters.get(PEPSParameters.PROVIDER_NAME_VALUE.toString());
    
    LOG.trace("Checking if SP is reliable");
    
    final IPersonalAttributeList pal = new PersonalAttributeList();
    pal.populate(attrList);
    
    // Validate if SP is trustworthy
    if (!spepsUtil.validateSP(parameters)) {
      throw new InvalidParameterPEPSException(
        PEPSUtil.getConfig(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID
          .errorCode()),
        PEPSUtil.getConfig(PEPSErrors.SP_COUNTRY_SELECTOR_INVALID_QAASPID
          .errorMessage()));
    }
    
    // check if SP is allowed to access requested attribute
    if (!spepsUtil.checkContents(spId, pal)) {
      LOG.info("BUSINESS EXCEPTION : SP can't request this attrs");
      throw new InvalidParameterPEPSException(
        PEPSUtil.getConfig(PEPSErrors.SP_COUNTRY_SELECTOR_SPNOTALLOWED
          .errorCode()),
        PEPSUtil.getConfig(PEPSErrors.SP_COUNTRY_SELECTOR_SPNOTALLOWED
          .errorMessage()));
    }
    
    LOG.trace("Saving authentication data.");
    
    final STORKAuthnRequest authData = new STORKAuthnRequest();
    authData.setPersonalAttributeList(pal);
    authData.setQaa(Integer.parseInt(qaa));
    // PEPS backwards compatibility
    if (StringUtils.isNotEmpty(providerName)) {
      authData.setSPID(spId);
      authData.setProviderName(providerName);
    } else {
      authData.setProviderName(spId);
    }
    authData.setAssertionConsumerServiceURL(parameters
      .get(PEPSParameters.SP_URL.toString()));
    authData.setDestination(getDestination());
    authData.setSpApplication(parameters.get(PEPSParameters.SPAPPLICATION
      .toString()));
    authData.setSpCountry(parameters.get(PEPSParameters.SPCOUNTRY.toString()));
    authData.setSpInstitution(parameters.get(PEPSParameters.SPINSTITUTION
      .toString()));
    authData.setSpSector(parameters.get(PEPSParameters.SPSECTOR.toString()));
    if(parameters.containsKey(PEPSParameters.SP_METADATA_URL.toString())){
      authData.setIssuer(parameters.get(PEPSParameters.SP_METADATA_URL.toString()));
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
   * Setter for spepsUtil.
   * 
   * @param nSpepsUtil The spepsUtil to set.
   */
  public void setSpepsUtil(final AUSPEPSUtil nSpepsUtil) {
    this.spepsUtil = nSpepsUtil;
  }
  
  /**
   * Getter for spepsUtil.
   * 
   * @return The spepsUtil value.
   */
  public AUSPEPSUtil getSpepsUtil() {
    return spepsUtil;
  }
  
}
