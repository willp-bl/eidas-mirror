package eu.stork.idp;

import java.util.ArrayList;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import eu.stork.peps.auth.engine.core.SAMLEngineEncryptionI;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import org.apache.log4j.Logger;

import eu.stork.peps.auth.commons.IPersonalAttributeList;
import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PersonalAttribute;
import eu.stork.peps.auth.commons.PersonalAttributeList;
import eu.stork.peps.auth.commons.STORKAuthnRequest;
import eu.stork.peps.auth.commons.STORKAuthnResponse;
import eu.stork.peps.auth.commons.STORKStatusCode;
import eu.stork.peps.auth.commons.STORKSubStatusCode;
import eu.stork.peps.auth.commons.exceptions.InternalErrorPEPSException;
import eu.stork.peps.auth.commons.exceptions.InvalidParameterPEPSException;
import eu.stork.peps.auth.commons.exceptions.SecurityPEPSException;
import eu.stork.peps.auth.engine.STORKSAMLEngine;

public class ProcessLogin {

	private static final Logger logger = Logger.getLogger(ProcessLogin.class.getName());
    private static final String SIGN_ASSERTION_PARAM="signAssertion";
    private String samlToken;
    private String username;
    private String callback;
	private String signAssertion;
	private String encryptAssertion;
	private Properties idpProperties = PEPSUtil.loadConfigs(Constants.IDP_PROPERTIES);

    private Properties loadConfigs(String path) {
        return PEPSUtil.loadConfigs(path);
    }

	public boolean processAuthentication(HttpServletRequest request, HttpServletResponse response){
		
		PEPSUtil.createInstance(loadConfigs("pepsUtil.properties"));
		
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		String samlToken = request.getParameter("samlToken");
		encryptAssertion = request.getParameter("encryptAssertion");

		STORKAuthnRequest authnRequest = validateRequest(samlToken);
		this.callback = authnRequest.getAssertionConsumerServiceURL();
		
		if( username==null || password==null ){
			sendErrorRedirect(authnRequest, request);
			return false;
		}
		
		Properties users = null;
		String pass = null;
		try {
			users = loadConfigs("user.properties");
			pass = users.getProperty(username);
		} catch (SecurityPEPSException e) {
			sendErrorRedirect(authnRequest, request);
		}			
		
		if(  pass == null || (!pass.equals(password)) ){
			sendErrorRedirect(authnRequest, request);
			return false;
		}
		
		this.username = username;
		
		IPersonalAttributeList attrList = authnRequest.getPersonalAttributeList();
        for (PersonalAttribute pa : attrList){
            String attrName = pa.getName();

            String value = users.getProperty(username + "." + attrName);
            if (value != null) {
                if(pa.isEmptyValue()) {
                    logger.trace("[processAuthentication] Setting: " + attrName + "=>" + value);
                    ArrayList<String> tmp = new ArrayList<String>();
                    tmp.add(value);
                    pa.setValue(tmp);
                    pa.setStatus(STORKStatusCode.STATUS_AVAILABLE.toString());
                }
            }
            else {
                if(!pa.isEmptyStatus()) {
                    pa.setStatus(STORKStatusCode.STATUS_NOT_AVAILABLE.toString());
                }
            }
            //attrList.put(attrName, pa);
        }

		sendRedirect(authnRequest, (PersonalAttributeList) attrList, request);
		
		return true;
	}
	
	private STORKAuthnRequest validateRequest(String samlToken){
		STORKAuthnRequest authnRequest;
		try {
			STORKSAMLEngine engine = getSamlEngineInstance();
			authnRequest = engine.validateSTORKAuthnRequest(PEPSUtil.decodeSAMLToken(samlToken));
		} catch (Exception e) {
			throw new InvalidParameterPEPSException(PEPSUtil
				.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
				PEPSUtil.getConfig(PEPSErrors.COLLEAGUE_REQ_INVALID_SAML
					.errorMessage()));
		}
		return authnRequest;
	}
	
	private void sendRedirect(STORKAuthnRequest authnRequest,
			PersonalAttributeList attrList, HttpServletRequest request) {
		try {
			String remoteAddress = request.getRemoteAddr();
			if (request.getHeader(PEPSParameters.HTTP_X_FORWARDED_FOR.toString()) != null)
				remoteAddress = request
						.getHeader(PEPSParameters.HTTP_X_FORWARDED_FOR.toString());
			else {
				if (request.getHeader(PEPSParameters.X_FORWARDED_FOR.toString()) != null)
					remoteAddress = request
							.getHeader(PEPSParameters.X_FORWARDED_FOR.toString());
			}

			STORKSAMLEngine engine = getSamlEngineInstance();
			STORKAuthnResponse responseAuthReq = new STORKAuthnResponse();
			for(PersonalAttribute pa:attrList){
				if(pa.isEmptyValue() && pa.isRequired()){
					pa.setStatus(STORKStatusCode.STATUS_NOT_AVAILABLE.toString());
				}
			}
			responseAuthReq.setPersonalAttributeList(attrList);
			responseAuthReq.setInResponseTo(authnRequest.getSamlId());
			String metadataUrl=idpProperties==null?null:idpProperties.getProperty(Constants.IDP_METADATA_URL);
			if(metadataUrl!=null && !metadataUrl.isEmpty()) {
				responseAuthReq.setIssuer(metadataUrl);
			}
			engine.setRequestIssuer(authnRequest.getIssuer());
			STORKAuthnResponse samlToken = engine.generateSTORKAuthnResponse(authnRequest, responseAuthReq, remoteAddress, false, Boolean.parseBoolean(request.getParameter(SIGN_ASSERTION_PARAM)));

			this.samlToken = PEPSUtil.encodeSAMLToken(samlToken.getTokenSaml());
		} catch (Exception e) {
			throw new InternalErrorPEPSException("0",
					"Error generating SAMLToken");
		}
	}

	private STORKSAMLEngine getSamlEngineInstance() throws STORKSAMLEngineException{
		STORKSAMLEngine engine = IDPUtil.createSAMLEngine(Constants.SAMLENGINE_NAME);
		Properties userProps = PEPSUtil.loadConfigs("samlengine.properties", false);
		if(userProps!=null && userProps.containsKey(SAMLEngineEncryptionI.DATA_ENCRYPTION_ALGORITHM)){
			engine.setEncrypterProperty(SAMLEngineEncryptionI.DATA_ENCRYPTION_ALGORITHM, userProps.getProperty(SAMLEngineEncryptionI.DATA_ENCRYPTION_ALGORITHM));
		}
		if(Boolean.parseBoolean(encryptAssertion)){
			engine.setEncrypterProperty(SAMLEngineEncryptionI.RESPONSE_ENCRYPTION_MANDATORY, encryptAssertion);
		}
		if(Boolean.parseBoolean(idpProperties.getProperty(IDPUtil.ACTIVE_METADATA_CHECK))) {
			engine.setMetadataProcessor(new IdPMetadataProcessor());
		}
		return engine;
	}

	private void sendErrorRedirect(STORKAuthnRequest authnRequest, HttpServletRequest request){
		STORKAuthnResponse samlTokenFail = new STORKAuthnResponse();
		try {
			samlTokenFail.setStatusCode(STORKStatusCode.RESPONDER_URI.toString());
			samlTokenFail.setSubStatusCode(STORKSubStatusCode.AUTHN_FAILED_URI.toString());
			samlTokenFail.setMessage("Credenciais inválidas!");
			STORKSAMLEngine engine = getSamlEngineInstance();
			engine.setRequestIssuer(authnRequest.getIssuer());
			String metadataUrl=idpProperties==null?null:idpProperties.getProperty(Constants.IDP_METADATA_URL);
			if(metadataUrl!=null && !metadataUrl.isEmpty()) {
				samlTokenFail.setIssuer(metadataUrl);
			}
			samlTokenFail = engine.generateSTORKAuthnResponseFail(authnRequest, samlTokenFail, request.getRemoteAddr(), false);
		} catch (Exception e) {
			throw new InternalErrorPEPSException("0", "Error generating SAMLToken");
		}
		this.samlToken = PEPSUtil.encodeSAMLToken(samlTokenFail.getTokenSaml());
	}

	
	/**
	 * @param samlToken the samlToken to set
	 */
	public void setSamlToken(String samlToken) {
		this.samlToken = samlToken;
	}

	/**
	 * @return the samlToken
	 */
	public String getSamlToken() {
		return samlToken;
	}

	/**
	 * @param username the username to set
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * @return the username
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * @param callback the callback to set
	 */
	public void setCallback(String callback) {
		this.callback = callback;
	}

	/**
	 * @return the callback
	 */
	public String getCallback() {
		return callback;
	}

    /**
     * @param signAssertion the signAssertion to set
     */
    public void setSignAssertion(String signAssertion) {
        this.signAssertion = signAssertion;
    }

    /**
     * @return the signAssertion value
     */
    public String getSignAssertion() {
        return signAssertion;
    }

	public String getEncryptAssertion() {
		return encryptAssertion;
	}

	public void setEncryptAssertion(String encryptAssertion) {
		this.encryptAssertion = encryptAssertion;
	}
}
