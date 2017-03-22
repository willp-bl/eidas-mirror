/*
 * Copyright (c) 2016 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.eidas.idp.metadata;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.opensymphony.xwork2.Action;
import com.opensymphony.xwork2.ActionSupport;

import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.engine.configuration.dom.EncryptionKey;
import eu.eidas.auth.engine.configuration.dom.SignatureKey;
import eu.eidas.auth.engine.metadata.Contact;
import eu.eidas.idp.Constants;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.opensaml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.exceptions.EIDASServiceException;
import eu.eidas.auth.engine.ProtocolEngineFactory;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.auth.engine.metadata.MetadataConfigParams;
import eu.eidas.auth.engine.metadata.MetadataGenerator;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 * This Action returns an xml containing IDP metadata
 *
 */
public class GenerateMetadataAction extends ActionSupport implements ServletRequestAware, ServletResponseAware {

	static final Logger logger = LoggerFactory.getLogger(GenerateMetadataAction.class.getName());
	private static final long serialVersionUID = -4744260243380919161L;

        private transient InputStream dataStream;

        private static final String INVALID_METADATA = "invalid metadata";
        private static final String ERROR_GENERATING_METADATA = "error generating metadata {}";
        Properties configs = EIDASUtil.loadConfigs(Constants.IDP_PROPERTIES);

        public String generateMetadata(){
		String metadata=INVALID_METADATA;
		try {
			ProtocolEngineI engine = ProtocolEngineFactory.getDefaultProtocolEngine(Constants.SAMLENGINE_NAME);
			MetadataGenerator generator = new MetadataGenerator();
			MetadataConfigParams mcp=new MetadataConfigParams();
			generator.setConfigParams(mcp);
			generator.initialize(engine);
			mcp.setEntityID(configs.getProperty(Constants.IDP_METADATA_URL));
                        putSSOSBindingLocation(mcp, SAMLConstants.SAML2_REDIRECT_BINDING_URI, Constants.SSOS_REDIRECT_LOCATION_URL);
                        putSSOSBindingLocation(mcp, SAMLConstants.SAML2_POST_BINDING_URI, Constants.SSOS_POST_LOCATION_URL);
			generator.addIDPRole();
            mcp.setTechnicalContact(getTechnicalContact(generator.getContactStrings()));
            mcp.setSupportContact(getSupportContact(generator.getContactStrings()));
            mcp.setSigningMethods(configs == null ? null : configs.getProperty(SignatureKey.SIGNATURE_ALGORITHM_WHITE_LIST.getKey()));
            mcp.setDigestMethods(configs == null ? null : configs.getProperty(SignatureKey.SIGNATURE_ALGORITHM_WHITE_LIST.getKey()));
            mcp.setEncryptionAlgorithms(configs == null ? null : configs.getProperty(EncryptionKey.ENCRYPTION_ALGORITHM_WHITE_LIST.getKey()));
            mcp.setOrganizationName(configs == null ? null : configs.getProperty(MetadataConfigParams.ORG_NAME));
			metadata = generator.generateMetadata();
		} catch(EIDASSAMLEngineException see){
			logger.error(ERROR_GENERATING_METADATA, see);
		}
		dataStream = new ByteArrayInputStream(EidasStringUtil.getBytes(metadata));
		return Action.SUCCESS;
	}

        private void putSSOSBindingLocation(MetadataConfigParams mcp,final String binding, final String locationKey){
            if (isValidSSOSBindingLocation(configs.getProperty(locationKey))) {
                mcp.getProtocolBindingLocation().put(binding, configs.getProperty(locationKey));
            } else {
                String msg = String.format("BUSINESS EXCEPTION : Missing property %3$s for binding %1$s at %2$s", binding, configs.getProperty(Constants.IDP_METADATA_URL), locationKey);
                logger.error(msg);
                throwSAMLEngineNoMetadataException();
            }
        }

         private boolean isValidSSOSBindingLocation(final String location) {
            return location != null;
        }

        private void throwSAMLEngineNoMetadataException() {
            final String exErrorCode = configs.getProperty(EidasErrorKey.SAML_ENGINE_NO_METADATA.errorCode());
            final String exErrorMessage = configs.getProperty(EidasErrorKey.SAML_ENGINE_NO_METADATA.errorMessage());
            throw new EIDASServiceException(exErrorCode, exErrorMessage);
        }

        @Override
	public void setServletRequest(HttpServletRequest request) {
        }

        @Override
	public void setServletResponse(HttpServletResponse response) {
        }

        public InputStream getInputStream(){
            return dataStream;
        }

	public void setInputStream(InputStream inputStream){
            dataStream=inputStream;
        }

    private Contact getTechnicalContact(String[][] source){
        return createContact(source[0]);
    }
    private Contact getSupportContact(String[][] source){
        return createContact(source[1]);
    }

    private Contact createContact(String[] propsNames){
        Contact contact=new Contact();
        contact.setCompany(propsNames!=null && propsNames.length>0 &&configs!=null?configs.getProperty(propsNames[0]):null);
        contact.setEmail(propsNames!=null && propsNames.length>1 &&configs!=null?configs.getProperty(propsNames[1]):null);
        contact.setGivenName(propsNames!=null && propsNames.length>2 &&configs!=null?configs.getProperty(propsNames[2]):null);
        contact.setSurName(propsNames!=null && propsNames.length>3 &&configs!=null?configs.getProperty(propsNames[3]):null);
        contact.setPhone(propsNames!=null && propsNames.length>4 &&configs!=null?configs.getProperty(propsNames[4]):null);
        return contact;
    }


}