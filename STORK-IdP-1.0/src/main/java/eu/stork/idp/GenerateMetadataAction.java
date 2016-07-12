/*
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 *
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */
package eu.stork.idp;

import com.opensymphony.xwork2.Action;
import com.opensymphony.xwork2.ActionSupport;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.metadata.MetadataConfigParams;
import eu.stork.peps.auth.engine.metadata.MetadataGenerator;
import eu.stork.peps.exceptions.SAMLEngineException;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * This Action returns an xml containing IDP metadata
 *
 */
public class GenerateMetadataAction extends ActionSupport implements ServletRequestAware, ServletResponseAware {
	

	static final Logger logger = LoggerFactory.getLogger(GenerateMetadataAction.class.getName());
	private static final long serialVersionUID = -4744260243380919161L;


	private HttpServletRequest request;
	private transient InputStream dataStream;
	public String generateMetadata(){
		String metadata=new String("invalid metadata");
		try {
			Properties configs = PEPSUtil.loadConfigs(Constants.IDP_PROPERTIES);
			STORKSAMLEngine engine = IDPUtil.createSAMLEngine(Constants.SAMLENGINE_NAME);
			MetadataGenerator generator = new MetadataGenerator();
			MetadataConfigParams mcp=new MetadataConfigParams();
			generator.setConfigParams(mcp);
			generator.initialize(engine);
			mcp.setEntityID(configs.getProperty(Constants.IDP_METADATA_URL));
			generator.addIDPRole();
			metadata = generator.generateMetadata();
		}catch(SAMLEngineException see){
			logger.error("error generating metadata {}", see);
		}catch(STORKSAMLEngineException see){
			logger.error("error generating metadata {}", see);
		}
		dataStream = new ByteArrayInputStream(metadata.getBytes());
		return Action.SUCCESS;
	}

	public void setServletRequest(HttpServletRequest request) {
		this.request = request;
	}

	public void setServletResponse(HttpServletResponse response) {
	}
	public InputStream getInputStream(){return dataStream;}
	public void setInputStream(InputStream inputStream){dataStream=inputStream;}



}