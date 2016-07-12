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

import eu.stork.peps.auth.AUPEPSUtil;
import eu.stork.peps.auth.ConcurrentMapService;
import eu.stork.peps.auth.commons.*;
import org.apache.commons.lang.StringUtils;
import org.owasp.esapi.StringUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * This Util class is used by {@link AUSPEPSSAML} and
 * {@link AUSPEPSCountrySelector} to get a configuration from a loaded
 * configuration file or to validate the SP.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com,
 *         paulo.ribeiro@multicert.com
 * @version $Revision: 1.7 $, $Date: 2011-02-18 02:02:39 $
 */
public final class AUSPEPSUtil extends AUPEPSUtil {

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AUSPEPSUtil.class.getName());

    /**
     * Configuration file.
     */
    private Properties configs;

    /**
     * Bypass all SP validations?
     */
    private boolean bypassValidation;

    /**
     * Minimum QAA Level Allowed.
     */
    private int minQAA;

    /**
     * Maximum QAA Level Allowed.
     */
    private int maxQAA;

    public AUSPEPSUtil(){
        // default constructor for use without concurrentMapService
    }
    public AUSPEPSUtil(final ConcurrentMapService concurrentMapService){
            // Obtaining the anti-replay cache service provider defined in configuration and call it for setting up cache
            setAntiReplayCache(concurrentMapService.getNewAntiReplayCache());
    }

    /**
     * Loads a specific property.
     *
     * @param configKey the key of the property to load.
     * @return String containing the value of the property.
     */
    public String loadConfig(final String configKey) {
        LOG.debug("Loading config file " + configKey);
        return getConfigs().getProperty(configKey);
    }

    /**
     * Loads the URL of a C-PEPS, with the Id pepId, from the properties file.
     *
     * @param pepId the Id of the C-PEPS.
     * @return String with the URL of the C-PEPS. null if no URL was found.
     */
    public String loadConfigPepsURL(final String pepId) {
        return loadCPEPSattribute(pepId, "url");
    }

    public String loadConfigPepsMetadataURL(final String pepId) {
        return loadCPEPSattribute(pepId, "metadata.url");
    }

    private String loadCPEPSattribute(final String pepId, String paramName){
        String retVal = null;
        final int nPeps =
                Integer.parseInt(configs.getProperty(PEPSParameters.PEPS_NUMBER
                        .toString()));
        LOG.debug("Number of C-PEPS: " + nPeps);

        // load URL
        for (int i = 1; i <= nPeps && retVal == null; i++) {
            final String cpepsCons = PEPSValues.CPEPS_PREFIX.index(i);
            if (configs.containsKey(cpepsCons)
                    && configs.getProperty(cpepsCons).equals(pepId)) {
                retVal = configs.getProperty(PEPSValues.CPEPS_PREFIX.attribute(paramName, i));
                LOG.debug("C-PEPS URL " + retVal);
            }
        }

        return retVal;

    }

    /**
     * Loads the skew time of a C-PEPS, with the Id pepId, from the properties file.
     *
     * @param pepId the Id of the C-PEPS.
     * @return String with the URL of the C-PEPS. null if no URL was found.
     */
    public Long loadConfigPepsTimeSkewInMillis(final String pepId) {
        LOG.trace("loadConfigPepsTimeSkewInMillis");
        Long retVal=null;
        if (StringUtils.isEmpty(pepId)){
            LOG.info("BUSINESS EXCEPTION : the pepsId is empty or null !");
            return Long.valueOf(0);
        }
        final int nPeps = Integer.parseInt(configs.getProperty(PEPSParameters.PEPS_NUMBER.toString()));
        LOG.debug("Number of C-PEPS: " + nPeps);
        for (int i = 1; i <= nPeps && retVal == null; i++) {
            final String cpepsCons = PEPSValues.CPEPS_PREFIX.index(i);
            if (configs.containsKey(cpepsCons) && configs.getProperty(cpepsCons).equals(pepId)) {
                if (StringUtils.isNotEmpty(configs.getProperty(PEPSValues.CPEPS_PREFIX.skew(i)))){
                    retVal = Long.parseLong(configs.getProperty(PEPSValues.CPEPS_PREFIX.skew(i)));
                    LOG.debug("C-PEPS SKEW " + retVal);
                } else {
                    LOG.error("C-PEPS SKEW is empty in peps.xml");
                    retVal = Long.valueOf(0);
                }
            }
        }
        return retVal;
    }

    /**
     * Checks if a specific Service Provider has the required access level and if
     * it is a known Service Provider.
     * otherwise.
     *
     * @param parameters       A map of attributes.
     * @return true is SP is valid; false otherwise.
     * @see Map
     * @see ISPEPSSAMLService
     */
    public boolean validateSP(final Map<String, String> parameters) {

        final String spID = parameters.get(PEPSParameters.SP_ID.toString());
        final String spQAALevel =
                parameters.get(PEPSParameters.SP_QAALEVEL.toString());
        final String spLoA =
                parameters.get(PEPSParameters.EIDAS_SERVICE_LOA.toString());
        final String loadedSpQAALevel = this.loadConfig(spID + ".qaalevel");

        if (spLoA==null && (!this.isValidQAALevel(spQAALevel)
                || (!bypassValidation && !this.isValidSPQAALevel(spQAALevel,
                loadedSpQAALevel)))) {

            LOG.info("BUSINESS EXCEPTION : " + spID + " is untrustable or has an invalid QAALevel: "
                    + spQAALevel);
            return false;
        }else if (spLoA!=null && EidasLoaLevels.getLevel(spLoA)==null){
            LOG.info("BUSINESS EXCEPTION : " + spID + " is untrustable or has an invalid LoA: " + spLoA);
            return false;
        }
        LOG.trace("BUSINESS EXCEPTION : " + spID + " is trustable and has either a valid QAALevel: " + spQAALevel+" or a valid LoA: "+spLoA);
        return true;
    }

    /**
     * Checks if the Service Provider's provider name matches the configured
     * certificate alias.
     *
     * @param providerName The SP's provider name.
     * @param spCertAlias  The configured SP's alias.
     * @return true if the SP's alias validations succeeded.
     */
    public boolean validateSPCertAlias(final String providerName,
                                       final String spCertAlias) {

        boolean retVal = true;

        final String providerNameAlias =
                providerName + PEPSValues.VALIDATION_SUFFIX.toString();
        final String pnAliasConf = (String) getConfigs().get(providerNameAlias);

        if (StringUtils.isBlank(pnAliasConf)) {
            LOG.info("BUSINESS EXCEPTION : Couldn't get alias' conf value!");
            retVal = false;
        } else {
            if (!PEPSValues.NONE.toString().equalsIgnoreCase(pnAliasConf)) {
                retVal =
                        StringUtils.lowerCase(pnAliasConf).equals(
                                StringUtils.lowerCase(spCertAlias));
            }
        }

        LOG.trace("Alias validation return value: " + retVal);
        return retVal;
    }

    /**
     * Checks if the configured QAALevel is greater than minQAALevel and less than
     * maxQAALevel.
     *
     * @param qaaLevel The QAA Level to validate.
     * @return True if the qaaLevel is valid. False otherwise.
     */
    private boolean isValidQAALevel(final String qaaLevel) {
        return StringUtils.isNumeric(qaaLevel)
                && Integer.parseInt(qaaLevel) >= this.getMinQAA()
                && Integer.parseInt(qaaLevel) <= this.getMaxQAA();
    }

    /**
     * Checks if the requested SP's QAALevel is less than configured SP's
     * QAALevel.
     *
     * @param spQAALevel   The QAA Level of the SP.
     * @param confQAALevel The QAA Level from the configurations.
     * @return True if spQAALevel is valid. False otherwise.
     */
    private boolean isValidSPQAALevel(final String spQAALevel,
                                      final String confQAALevel) {

        return StringUtils.isNumeric(spQAALevel)
                && StringUtils.isNumeric(confQAALevel)
                && Integer.parseInt(confQAALevel) >= Integer.parseInt(spQAALevel);
    }

    private boolean checkPermission(final String permission, final IPersonalAttributeList attributeList){
        LOG.trace("List of permitted attributes: " + permission);
        // Creates an array list from a String in the format perm1;perm2;permN;.
        final String[] perms =
                permission.split(PEPSValues.ATTRIBUTE_SEP.toString());
        final List<String> permissions =
                new ArrayList<String>(Arrays.asList(perms));
        for (final PersonalAttribute pa : attributeList) {
            if (!permissions.contains(pa.getName())) {
                LOG.trace("False:No Permission - " + pa.getName());
                return false;
            }
        }
        return true;

    }
    /**
     * Checks if the Service provider, with the ID spID has access to the
     * requested attributes.
     *
     * @param spId          The id of the SP.
     * @param attributeList The requested attributes.
     * @return True if the SP has access to the contents, False otherwise.
     * @see IPersonalAttributeList
     */
    public boolean checkContents(final String spId,
                                 final IPersonalAttributeList attributeList) {

      final String permission = StringUtilities.isEmpty(loadConfig(spId)) ?
              loadConfig(PEPSValues.DEFAULT.toString()): loadConfig(spId);

      if(!StringUtilities.isEmpty(permission)) {
        if (PEPSValues.ALL.toString().equals(permission)) {
          LOG.debug("True:ALL_VALUES");
          return true;
        } else if (PEPSValues.NONE.toString().equals(permission)) {
          LOG.debug("False:NO_VALUES");
          return false;
        } else {
            return checkPermission(permission, attributeList);
        }
      }else{
        LOG.debug("No attribute configuration found!");
        return false;
      }
    }

    /**
     * Setter for bypassValidation.
     *
     * @param byPassValidation The bypassValidation to set.
     */
    public void setBypassValidation(final boolean byPassValidation) {
        this.bypassValidation = byPassValidation;
    }

    /**
     * Getter for bypassValidation.
     *
     * @return The bypassValidation value.
     */
    public boolean isBypassValidation() {
        return bypassValidation;
    }

    /**
     * Setter for configs.
     *
     * @param confs The configs to set.
     * @see Properties
     */
    public void setConfigs(final Properties confs) {
        this.configs = confs;
    }

    /**
     * Getter for configs.
     *
     * @return configs The configs value.
     * @see Properties
     */
    public Properties getConfigs() {
        return configs;
    }

    /**
     * Getter for minQAA.
     *
     * @return The minQAA value.
     */
    public int getMinQAA() {
        return minQAA;
    }

    /**
     * Setter for minQAA.
     *
     * @param nMinQAA The new minQAA value.
     */
    public void setMinQAA(final int nMinQAA) {
        this.minQAA = nMinQAA;
    }

    /**
     * Setter for maxQAA.
     *
     * @param nMaxQAA The new maxQAA value.
     */
    public void setMaxQAA(final int nMaxQAA) {
        this.maxQAA = nMaxQAA;
    }

    /**
     * Getter for maxQAA.
     *
     * @return The maxQAA value.
     */
    public int getMaxQAA() {
        return maxQAA;
    }
}
