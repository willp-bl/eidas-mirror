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
package eu.eidas.node.utils;

import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLEngineEncryptionI;
import eu.eidas.auth.engine.core.SAMLEngineSignI;
import eu.eidas.auth.engine.metadata.Contact;
import eu.eidas.auth.engine.metadata.MetadataConfigParams;
import eu.eidas.auth.engine.metadata.MetadataGenerator;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.node.init.EidasSamlEngineFactory;

import org.apache.commons.lang.StringUtils;
import org.opensaml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

/**
 * generator for Eidas metadata
 */
public class EidasNodeMetadataGenerator {
    /**
     * Logger object.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EidasNodeMetadataGenerator.class.getName());

    //saml engine names
    //Connector as Idp
    private String samlConnectorIDP;
    //Connector as SP
    private String samlConnectorSP;
    //ProxyServive as Idp
    private String samlServiceIDP;
    //ProxyService as SP
    private String samlServiceSP;

    private String connectorMetadataUrl;
    private String serviceMetadataUrl;

    private EidasSamlEngineFactory samlEngineFactory;
    private String connectorCountry;
    private String connectorUrl;
    private String serviceCountry;
    private String serviceUrl;
    private String assertionUrl;
    private Properties nodeProps;
    private long validityDuration;

    public String getSamlConnectorIDP() {
        return samlConnectorIDP;
    }

    public void setSamlConnectorIDP(String samlConnectorIDP) {
        this.samlConnectorIDP = samlConnectorIDP;
    }

    public String getSamlConnectorSP() {
        return samlConnectorSP;
    }

    public void setSamlConnectorSP(String samlConnectorSP) {
        this.samlConnectorSP = samlConnectorSP;
    }

    public String getSamlServiceIDP() {
        return samlServiceIDP;
    }

    public void setSamlServiceIDP(String samlServiceIDP) {
        this.samlServiceIDP = samlServiceIDP;
    }

    public String getSamlServiceSP() {
        return samlServiceSP;
    }

    public void setSamlServiceSP(String samlServiceSP) {
        this.samlServiceSP = samlServiceSP;
    }

    public EidasSamlEngineFactory getSamlEngineFactory() {
        return samlEngineFactory;
    }

    public void setSamlEngineFactory(EidasSamlEngineFactory samlEngineFactory) {
        this.samlEngineFactory = samlEngineFactory;
    }

    public String getConnectorMetadataUrl() {
        return connectorMetadataUrl;
    }

    public void setConnectorMetadataUrl(String connectorMetadataUrl) {
        this.connectorMetadataUrl = connectorMetadataUrl;
    }

    public String getServiceMetadataUrl() {
        return serviceMetadataUrl;
    }

    public void setServiceMetadataUrl(String serviceMetadataUrl) {
        this.serviceMetadataUrl = serviceMetadataUrl;
    }

    private static final String INVALID_METADATA="invalid metadata";

    public String generateConnectorMetadata(){
        return helperGenerateMetadata(samlConnectorSP, samlConnectorIDP, connectorMetadataUrl,getConnectorCountry(),CONNECTOR_CONTACTS,getConnectorUrl(), null);
    }

    public String generateServiceMetadata(){
        String loA=null;
        if(getNodeProps()!=null){
            loA=getNodeProps().getProperty(EIDASValues.EIDAS_SERVICE_LOA.toString());
        }
        return helperGenerateMetadata(samlServiceSP, samlServiceIDP, serviceMetadataUrl,getServiceCountry(),SERVICE_CONTACTS,getServiceUrl(), loA);
    }

    private String helperGenerateMetadata(String spEngineName, String idpEngineName, String url, String country, String[][] contactsProperties, String siteUrl, String loA){
        String metadata=INVALID_METADATA;
        EIDASSAMLEngine spEngine=null;
        EIDASSAMLEngine idpEngine=null;
        if(url!=null && !url.isEmpty()) {
            try {
                if(!StringUtils.isEmpty(spEngineName)) {
                    spEngine = getSamlEngineFactory().getEngine(spEngineName, getNodeProps());
                }
                if(!StringUtils.isEmpty(idpEngineName)) {
                    idpEngine = getSamlEngineFactory().getEngine(idpEngineName, getNodeProps());
                }
                MetadataGenerator generator =  generateMetadata(spEngine, idpEngine, url);
                MetadataConfigParams mcp=generator.getConfigParams();
                mcp.setCountryName(country);
                mcp.setNodeUrl(siteUrl);
                mcp.setAssuranceLevel(loA);
                mcp.setAssertionConsumerUrl(assertionUrl);
                mcp.getProtocolBinding().add(SAMLConstants.SAML2_POST_BINDING_URI);
                mcp.getProtocolBinding().add(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                mcp.setSigningMethods(nodeProps == null ? null : nodeProps.getProperty(SAMLEngineSignI.SIGNATURE_ALGORITHMS_WHITELIST));
                mcp.setDigestMethods(nodeProps == null ? null : nodeProps.getProperty(SAMLEngineSignI.SIGNATURE_ALGORITHMS_WHITELIST));
                mcp.setEncryptionAlgorithms(nodeProps == null ? null : nodeProps.getProperty(SAMLEngineEncryptionI.ENCRYPTION_ALGORITHM_WHITELIST));
                mcp.setSpType(nodeProps == null ? null : nodeProps.getProperty(EIDASValues.EIDAS_SPTYPE.toString()));
                mcp.setValidityDuration(validityDuration);
                mcp.setTechnicalContact(getTechnicalContact(contactsProperties));
                mcp.setSupportContact(getSupportContact(contactsProperties));
                return generator.generateMetadata();
            } catch (SAMLEngineException samlexc) {
                LOGGER.info("ERROR : Error creating Node metadata " + samlexc.getMessage());
                LOGGER.debug("ERROR : Error creating Node metadata ",samlexc);
                if(EIDASErrors.isErrorCode(samlexc.getErrorCode())){
                    EidasNodeErrorUtil.processSAMLEngineException(samlexc, LOGGER, EIDASErrors.SAML_ENGINE_NO_METADATA);
                }
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
    private MetadataGenerator generateMetadata(EIDASSAMLEngine spEngine, EIDASSAMLEngine idpEngine, String url) throws SAMLEngineException{
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

    public String getConnectorCountry() {
        return connectorCountry;
    }

    public void setConnectorCountry(String connectorCountry) {
        this.connectorCountry = connectorCountry;
    }

    public String getConnectorUrl() {
        return connectorUrl;
    }

    public void setConnectorUrl(String connectorUrl) {
        this.connectorUrl = connectorUrl;
    }

    public String getServiceCountry() {
        return serviceCountry;
    }

    public void setServiceCountry(String serviceCountry) {
        this.serviceCountry = serviceCountry;
    }

    public String getServiceUrl() {
        return serviceUrl;
    }

    public void setServiceUrl(String serviceUrl) {
        this.serviceUrl = serviceUrl;
    }

    public Properties getNodeProps() {
        return nodeProps;
    }

    public void setNodeProps(Properties nodeProps) {
        this.nodeProps = nodeProps;
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

    private static final String CONNECTOR_TECHNICAL_CONTACT_PROPS[]={"connector.contact.technical.company", "connector.contact.technical.email", "connector.contact.technical.givenname", "connector.contact.technical.surname", "connector.contact.technical.phone"};
    private static final String CONNECTOR_SUPPORT_CONTACT_PROPS[]={"connector.contact.support.company", "connector.contact.support.email", "connector.contact.support.givenname", "connector.contact.support.surname", "connector.contact.support.phone"};
    private static final String CONNECTOR_CONTACTS[][]={CONNECTOR_TECHNICAL_CONTACT_PROPS, CONNECTOR_SUPPORT_CONTACT_PROPS};
    private static final String SERVICE_TECHNICAL_CONTACT_PROPS[]={"service.contact.technical.company", "service.contact.technical.email", "service.contact.technical.givenname", "service.contact.technical.surname", "service.contact.technical.phone"};
    private static final String SERVICE_SUPPORT_CONTACT_PROPS[]={"service.contact.support.company", "service.contact.support.email", "service.contact.support.givenname", "service.contact.support.surname", "service.contact.support.phone"};
    private static final String SERVICE_CONTACTS[][]={SERVICE_TECHNICAL_CONTACT_PROPS, SERVICE_SUPPORT_CONTACT_PROPS};

    private Contact getTechnicalContact(String[][] source){
        return createContact(source[0]);
    }
    private Contact getSupportContact(String[][] source){
        return createContact(source[1]);
    }
    private Contact createContact(String[] propsNames){
        Contact contact=new Contact();
        contact.setCompany(propsNames!=null && propsNames.length>0 &&nodeProps!=null?nodeProps.getProperty(propsNames[0]):null);
        contact.setEmail(propsNames!=null && propsNames.length>1 &&nodeProps!=null?nodeProps.getProperty(propsNames[1]):null);
        contact.setGivenName(propsNames!=null && propsNames.length>2 &&nodeProps!=null?nodeProps.getProperty(propsNames[2]):null);
        contact.setSurName(propsNames!=null && propsNames.length>3 &&nodeProps!=null?nodeProps.getProperty(propsNames[3]):null);
        contact.setPhone(propsNames!=null && propsNames.length>4 &&nodeProps!=null?nodeProps.getProperty(propsNames[4]):null);
        return contact;
    }


}
