package eu.stork.sp;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.opensymphony.xwork2.Action;
import com.opensymphony.xwork2.ActionSupport;

import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnResponse;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.exceptions.STORKSAMLEngineException;

/**
 * This Action recives a SAML Response, shows it to the user and then validates it getting the attributes values
 * @author iinigo
 *
 */
public class ReturnAction extends ActionSupport implements ServletRequestAware, ServletResponseAware {
	
	private static final long serialVersionUID = 3660074009157921579L;

	private static final String SAML_VALIDATION_ERROR="Could not validate token for Saml Response";
	
	static final Logger logger = LoggerFactory.getLogger(IndexAction.class.getName());
	
	private String SAMLResponse;
	private String samlResponseXML;
	
	private List<PersonalAttribute> attrList;
	
	private HttpServletRequest request;
	private Properties configs;
	private String providerName;
	//private static String spUrl;	

	/**
	 * Translates the SAMLResponse to XML format in order to be shown in the JSP
	 * @return
	 */
	public String execute(){
		
		configs = SPUtil.loadSPConfigs();

		providerName = configs.getProperty(Constants.PROVIDER_NAME);
				
		byte[] decSamlToken = PEPSUtil.decodeSAMLToken(SAMLResponse);		
		samlResponseXML = new String(decSamlToken);
		
		return Action.SUCCESS;
	}
	
	/**
	 * Validates the request and displays the value of the requested attributes
	 * @return	 
	 */
	public String populate(){			
				
		STORKAuthnResponse authnResponse = null;
		IPersonalAttributeList personalAttributeList = null;
		
		//spUrl = configs.getProperty(Constants.SP_URL);
		
		//Decodes SAML Response
		byte[] decSamlToken = PEPSUtil.decodeSAMLToken(SAMLResponse);
		
		//Get SAMLEngine instance

		try {
			STORKSAMLEngine engine = SPUtil.createSAMLEngine(Constants.SP_CONF);
			//validate SAML Token
			authnResponse = engine.validateSTORKAuthnResponse(decSamlToken, (String) request.getRemoteHost(), 0);
		}catch(STORKSAMLEngineException e){	
			logger.error(e.getMessage());
			if(StringUtils.isEmpty(e.getErrorDetail())) {
				throw new ApplicationSpecificServiceException(SAML_VALIDATION_ERROR, e.getErrorMessage());
			}else{
				throw new ApplicationSpecificServiceException(SAML_VALIDATION_ERROR, e.getErrorDetail());
			}
		}			
		
		if(authnResponse.isFail()){
			throw new ApplicationSpecificServiceException("Saml Response is fail", authnResponse.getMessage());			
		}else{	
						
			//Get attributes
			personalAttributeList = authnResponse.getPersonalAttributeList();			
			
			/*////////////////////////TESTING CANONICAL RESIDDENCE ADDRESS///////////////////////
			PersonalAttribute canonicalResidenceAddress = new PersonalAttribute();
			canonicalResidenceAddress.setName("canonicalResidenceAddress");
			canonicalResidenceAddress.setIsRequired(true);
			canonicalResidenceAddress.setStatus(STORKStatusCode.STATUS_AVAILABLE);
								
			HashMap<String, String> address = new HashMap<String, String>();
			address.put("state", "ES");
			address.put("municipalityCode", "MA001");	
			address.put("town", "Madrid");
			address.put("postalCode", "28038");
			address.put("streetName", "Marchamalo");
			address.put("streetNumber", "3");
			address.put("apartamentNumber", "5 E");
			canonicalResidenceAddress.setComplexValue(address);
						
			personalAttributeList.add(canonicalResidenceAddress);
			////////////////////////TESTING CANONICAL RESIDDENCE ADDRESS///////////////////////*/

			List<PersonalAttribute> attrList = new ArrayList<PersonalAttribute>();
			for(PersonalAttribute pa:personalAttributeList){
				//should use the iterator because it provides the items in their insert order
				attrList.add(pa);
			}

			setAttrList(attrList);
									
			return "populate";
		}
	}
	
	public void setServletRequest(HttpServletRequest request) {
		this.request = request;
	}

	public void setServletResponse(HttpServletResponse response) {
	}
	
	public void setAttrList(List<PersonalAttribute> attrList) {
		this.attrList = attrList;
	}

	public List<PersonalAttribute> getAttrList() {
		return attrList;
	}	

	public String getProviderName() {
		return providerName;
	}

	public void setProviderName(String providerName) {
		this.providerName = providerName;
	}	
	
//	public String getSpUrl() {
//		return spUrl;
//	}

//	public void setSpUrl(String spUrl) {
//		ReturnAction.spUrl = spUrl;
//	}

	public String getSAMLResponse() {
		return SAMLResponse;
	}

	public void setSAMLResponse(String samlResponse) {
		this.SAMLResponse = samlResponse;
	}

	public String getSamlResponseXML() {
		return samlResponseXML;
	}

	public void setSamlResponseXML(String samlResponseXML) {
		this.samlResponseXML = samlResponseXML;
	}
	
	
}