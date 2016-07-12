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
package eu.stork.peps.utils;

import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.core.SAMLEngineEncryptionI;
import eu.stork.peps.auth.engine.core.SAMLEngineSignI;
import eu.stork.peps.auth.engine.metadata.Contact;
import eu.stork.peps.auth.engine.metadata.MetadataConfigParams;
import eu.stork.peps.auth.engine.metadata.MetadataGenerator;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.init.StorkSAMLEngineFactory;
import org.apache.commons.lang.StringUtils;
import org.opensaml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;

import java.util.Properties;

/**
 * generator for PEPS metadata
 */
public class PEPSMetadataGenerator {
    /**
     * Logger object.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PEPSMetadataGenerator.class.getName());

    //saml engine names
    //SPEPS as Idp
    private String samlSPEPSIDP;
    //SPEPS as SP
    private String samlSPEPSSP;
    //CPEPS as Idp
    private String samlCPEPSIDP;
    //CPEPS as SP
    private String samlCPEPSSP;

    private String spepsMetadataUrl;
    private String cpepsMetadataUrl;

    private StorkSAMLEngineFactory samlEngineFactory;
    private String spepsCountry;
    private String spepsUrl;
    private String cpepsCountry;
    private String cpepsUrl;
    private String assertionUrl;
    private Properties pepsProps;
    private long validityDuration;

    public String getSamlSPEPSIDP() {
        return samlSPEPSIDP;
    }

    public void setSamlSPEPSIDP(String samlSPEPSIDP) {
        this.samlSPEPSIDP = samlSPEPSIDP;
    }

    public String getSamlSPEPSSP() {
        return samlSPEPSSP;
    }

    public void setSamlSPEPSSP(String samlSPEPSSP) {
        this.samlSPEPSSP = samlSPEPSSP;
    }

    public String getSamlCPEPSIDP() {
        return samlCPEPSIDP;
    }

    public void setSamlCPEPSIDP(String samlCPEPSIDP) {
        this.samlCPEPSIDP = samlCPEPSIDP;
    }

    public String getSamlCPEPSSP() {
        return samlCPEPSSP;
    }

    public void setSamlCPEPSSP(String samlCPEPSSP) {
        this.samlCPEPSSP = samlCPEPSSP;
    }

    public StorkSAMLEngineFactory getSamlEngineFactory() {
        return samlEngineFactory;
    }

    public void setSamlEngineFactory(StorkSAMLEngineFactory samlEngineFactory) {
        this.samlEngineFactory = samlEngineFactory;
    }

    public String getSpepsMetadataUrl() {
        return spepsMetadataUrl;
    }

    public void setSpepsMetadataUrl(String spepsMetadataUrl) {
        this.spepsMetadataUrl = spepsMetadataUrl;
    }

    public String getCpepsMetadataUrl() {
        return cpepsMetadataUrl;
    }

    public void setCpepsMetadataUrl(String cpepsMetadataUrl) {
        this.cpepsMetadataUrl = cpepsMetadataUrl;
    }

    private static final String INVALID_METADATA="invalid metadata";

    public String generateSPEPSMetadata(){
        return helperGenerateMetadata(samlSPEPSSP, samlSPEPSIDP, spepsMetadataUrl,getSpepsCountry(),SPEPS_CONTACTS,getSpepsUrl(), null);
    }

    public String generateCPEPSMetadata(){
        String loA=null;
        if(getPepsProps()!=null){
            loA=getPepsProps().getProperty(PEPSValues.EIDAS_SERVICE_LOA.toString());
        }
        return helperGenerateMetadata(samlCPEPSSP, samlCPEPSIDP, cpepsMetadataUrl,getCpepsCountry(),CPEPS_CONTACTS,getCpepsUrl(), loA);
    }

    private String helperGenerateMetadata(String spEngineName, String idpEngineName, String url, String country, String[][] contactsProperties, String siteUrl, String loA){
        String metadata=INVALID_METADATA;
        STORKSAMLEngine spEngine=null;
        STORKSAMLEngine idpEngine=null;
        if(url!=null && !url.isEmpty()) {
            try {
                if(!StringUtils.isEmpty(spEngineName)) {
                    spEngine = getSamlEngineFactory().getEngine(spEngineName, getPepsProps());
                }
                if(!StringUtils.isEmpty(idpEngineName)) {
                    idpEngine = getSamlEngineFactory().getEngine(idpEngineName, getPepsProps());
                }
                MetadataGenerator generator =  generateMetadata(spEngine, idpEngine, url);
                MetadataConfigParams mcp=generator.getConfigParams();
                mcp.setCountryName(country);
                mcp.setNodeUrl(siteUrl);
                mcp.setAssuranceLevel(loA);
                mcp.setAssertionConsumerUrl(assertionUrl);
                mcp.getProtocolBinding().add(SAMLConstants.SAML2_POST_BINDING_URI);
                mcp.getProtocolBinding().add(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                mcp.setSigningMethods(pepsProps == null ? null : pepsProps.getProperty(SAMLEngineSignI.SIGNATURE_ALGORITHMS_WHITELIST));
                mcp.setDigestMethods(pepsProps == null ? null : pepsProps.getProperty(SAMLEngineSignI.SIGNATURE_ALGORITHMS_WHITELIST));
                mcp.setEncryptionAlgorithms(pepsProps == null ? null : pepsProps.getProperty(SAMLEngineEncryptionI.ENCRYPTION_ALGORITHM_WHITELIST));
                mcp.setSpType(pepsProps == null ? null : pepsProps.getProperty(PEPSValues.EIDAS_SPTYPE.toString()));
                mcp.setValidityDuration(validityDuration);
                mcp.setTechnicalContact(getTechnicalContact(contactsProperties));
                mcp.setSupportContact(getSupportContact(contactsProperties));
                return generator.generateMetadata();
            } catch (SAMLEngineException samlexc) {
                LOGGER.info("ERROR : Error creating PEPS metadata " + samlexc.getMessage());
                LOGGER.debug("ERROR : Error creating PEPS metadata ",samlexc);
            }finally{
                if(spEngine!=null){
                    getSamlEngineFactory().releaseEngine(spEngine);
                }
                if(idpEngine!=null){
                    getSamlEngineFactory().releaseEngine(idpEngine);
                }
            }
        }
        return metadata;
    }
    private MetadataGenerator generateMetadata(STORKSAMLEngine spEngine, STORKSAMLEngine idpEngine, String url) throws SAMLEngineException{
        MetadataGenerator generator = new MetadataGenerator();
        MetadataConfigParams mcp=new MetadataConfigParams();
        generator.setConfigParams(mcp);
        generator.initialize(spEngine, idpEngine);
        mcp.setEntityID(url);
        if(idpEngine!=null) {
            generator.addIDPRole();
        }
        if(spEngine!=null) {
            generator.addSPRole();
        }
        return generator;
    }

    private static final String SPEPS_TECHNICAL_CONTACT_PROPS[]={"speps.contact.technical.company", "speps.contact.technical.email", "speps.contact.technical.givenname", "speps.contact.technical.surname", "speps.contact.technical.phone"};
    private static final String SPEPS_SUPPORT_CONTACT_PROPS[]={"speps.contact.support.company", "speps.contact.support.email", "speps.contact.support.givenname", "speps.contact.support.surname", "speps.contact.support.phone"};
    private static final String SPEPS_CONTACTS[][]={SPEPS_TECHNICAL_CONTACT_PROPS, SPEPS_SUPPORT_CONTACT_PROPS};
    private static final String CPEPS_TECHNICAL_CONTACT_PROPS[]={"cpeps.contact.technical.company", "cpeps.contact.technical.email", "cpeps.contact.technical.givenname", "cpeps.contact.technical.surname", "cpeps.contact.technical.phone"};
    private static final String CPEPS_SUPPORT_CONTACT_PROPS[]={"cpeps.contact.support.company", "cpeps.contact.support.email", "cpeps.contact.support.givenname", "cpeps.contact.support.surname", "cpeps.contact.support.phone"};
    private static final String CPEPS_CONTACTS[][]={CPEPS_TECHNICAL_CONTACT_PROPS, CPEPS_SUPPORT_CONTACT_PROPS};

    private Contact getTechnicalContact(String[][] source){
        return createContact(source[0]);
    }
    private Contact getSupportContact(String[][] source){
        return createContact(source[1]);
    }
    private Contact createContact(String[] propsNames){
        Contact contact=new Contact();
        contact.setCompany(propsNames!=null && propsNames.length>0 &&pepsProps!=null?pepsProps.getProperty(propsNames[0]):null);
        contact.setEmail(propsNames!=null && propsNames.length>1 &&pepsProps!=null?pepsProps.getProperty(propsNames[1]):null);
        contact.setGivenName(propsNames!=null && propsNames.length>2 &&pepsProps!=null?pepsProps.getProperty(propsNames[2]):null);
        contact.setSurName(propsNames!=null && propsNames.length>3 &&pepsProps!=null?pepsProps.getProperty(propsNames[3]):null);
        contact.setPhone(propsNames!=null && propsNames.length>4 &&pepsProps!=null?pepsProps.getProperty(propsNames[4]):null);
        return contact;
    }

    public String getSpepsCountry() {
        return spepsCountry;
    }

    public void setSpepsCountry(String spepsCountry) {
        this.spepsCountry = spepsCountry;
    }

    public String getSpepsUrl() {
        return spepsUrl;
    }

    public void setSpepsUrl(String spepsUrl) {
        this.spepsUrl = spepsUrl;
    }

    public String getCpepsCountry() {
        return cpepsCountry;
    }

    public void setCpepsCountry(String cpepsCountry) {
        this.cpepsCountry = cpepsCountry;
    }

    public String getCpepsUrl() {
        return cpepsUrl;
    }

    public void setCpepsUrl(String cpepsUrl) {
        this.cpepsUrl = cpepsUrl;
    }

    public Properties getPepsProps() {
        return pepsProps;
    }

    public void setPepsProps(Properties pepsProps) {
        this.pepsProps = pepsProps;
    }

    public String getAssertionUrl() {
        return assertionUrl;
    }

    public void setAssertionUrl(String assertionUrl) {
        this.assertionUrl = assertionUrl;
    }

    public long getValidityDuration() {
        return validityDuration;
    }

    public void setValidityDuration(long validityDuration) {
        this.validityDuration = validityDuration;
    }
}
