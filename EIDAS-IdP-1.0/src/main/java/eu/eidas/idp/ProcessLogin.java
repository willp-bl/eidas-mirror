package eu.eidas.idp;

import java.util.ArrayList;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import eu.eidas.auth.commons.IPersonalAttributeList;
import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.PersonalAttribute;
import eu.eidas.auth.commons.PersonalAttributeList;
import eu.eidas.auth.commons.EIDASAuthnRequest;
import eu.eidas.auth.commons.EIDASAuthnResponse;
import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EIDASSubStatusCode;
import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLEngineEncryptionI;
import eu.eidas.auth.engine.metadata.MetadataUtil;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import org.apache.log4j.Logger;

public class ProcessLogin {

	private static final Logger logger = Logger.getLogger(ProcessLogin.class.getName());
    private static final String SIGN_ASSERTION_PARAM="signAssertion";
    private String samlToken;
    private String username;
    private String callback;
	private String signAssertion;
	private String encryptAssertion;
	private String eidasLoa;
	private Properties idpProperties = EIDASUtil.loadConfigs(Constants.IDP_PROPERTIES);

    private Properties loadConfigs(String path) {
        return EIDASUtil.loadConfigs(path);
    }

	public boolean processAuthentication(HttpServletRequest request, HttpServletResponse response){
		
		EIDASUtil.createInstance(loadConfigs("eidasUtil.properties"));
		
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		String samlToken = request.getParameter("samlToken");
		encryptAssertion = request.getParameter("encryptAssertion");
		eidasLoa = request.getParameter("eidasloa");

		EIDASAuthnRequest authnRequest = validateRequest(samlToken);
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
		} catch (SecurityEIDASException e) {
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
                    pa.setStatus(EIDASStatusCode.STATUS_AVAILABLE.toString());
                }
            }
            else {
                if(!pa.isEmptyStatus()) {
                    pa.setStatus(EIDASStatusCode.STATUS_NOT_AVAILABLE.toString());
                }
            }
            //attrList.put(attrName, pa);
        }

		sendRedirect(authnRequest, (PersonalAttributeList) attrList, request);
		
		return true;
	}
	
	private EIDASAuthnRequest validateRequest(String samlToken){
		EIDASAuthnRequest authnRequest;
		try {
			EIDASSAMLEngine engine = getSamlEngineInstance();
			authnRequest = engine.validateEIDASAuthnRequest(EIDASUtil.decodeSAMLToken(samlToken));
		} catch (Exception e) {
			throw new InvalidParameterEIDASException(EIDASUtil
				.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
				EIDASUtil.getConfig(EIDASErrors.COLLEAGUE_REQ_INVALID_SAML
					.errorMessage()));
		}
		return authnRequest;
	}
	
	private void sendRedirect(EIDASAuthnRequest authnRequest,
			PersonalAttributeList attrList, HttpServletRequest request) {
		try {
			String remoteAddress = request.getRemoteAddr();
			if (request.getHeader(EIDASParameters.HTTP_X_FORWARDED_FOR.toString()) != null)
				remoteAddress = request
						.getHeader(EIDASParameters.HTTP_X_FORWARDED_FOR.toString());
			else {
				if (request.getHeader(EIDASParameters.X_FORWARDED_FOR.toString()) != null)
					remoteAddress = request
							.getHeader(EIDASParameters.X_FORWARDED_FOR.toString());
			}

			EIDASSAMLEngine engine = getSamlEngineInstance();
			EIDASAuthnResponse responseAuthReq = new EIDASAuthnResponse();
			for(PersonalAttribute pa:attrList){
				if(pa.isEmptyValue() && pa.isRequired()){
					pa.setStatus(EIDASStatusCode.STATUS_NOT_AVAILABLE.toString());
				}
			}
			responseAuthReq.setPersonalAttributeList(attrList);
			responseAuthReq.setInResponseTo(authnRequest.getSamlId());
			if(callback==null){
				authnRequest.setAssertionConsumerServiceURL(MetadataUtil.getAssertionUrlFromMetadata(new IdPMetadataProcessor(), engine, authnRequest));
				callback=authnRequest.getAssertionConsumerServiceURL();
			}
			String metadataUrl=idpProperties==null?null:idpProperties.getProperty(Constants.IDP_METADATA_URL);
			if(metadataUrl!=null && !metadataUrl.isEmpty()) {
				responseAuthReq.setIssuer(metadataUrl);
			}
			engine.setRequestIssuer(authnRequest.getIssuer());
			responseAuthReq.setAssuranceLevel(eidasLoa);
			EIDASAuthnResponse samlToken = engine.generateEIDASAuthnResponse(authnRequest, responseAuthReq, remoteAddress, false, Boolean.parseBoolean(request.getParameter(SIGN_ASSERTION_PARAM)));

			this.samlToken = EIDASUtil.encodeSAMLToken(samlToken.getTokenSaml());
		} catch (Exception e) {
			throw new InternalErrorEIDASException("0",
					"Error generating SAMLToken");
		}
	}

	private EIDASSAMLEngine getSamlEngineInstance() throws EIDASSAMLEngineException{
		EIDASSAMLEngine engine = IDPUtil.createSAMLEngine(Constants.SAMLENGINE_NAME);
		Properties userProps = EIDASUtil.loadConfigs("samlengine.properties", false);
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

	private void sendErrorRedirect(EIDASAuthnRequest authnRequest, HttpServletRequest request){
		EIDASAuthnResponse samlTokenFail = new EIDASAuthnResponse();
		try {
			samlTokenFail.setStatusCode(EIDASStatusCode.RESPONDER_URI.toString());
			samlTokenFail.setSubStatusCode(EIDASSubStatusCode.AUTHN_FAILED_URI.toString());
			samlTokenFail.setMessage("Credenciais inválidas!");
			EIDASSAMLEngine engine = getSamlEngineInstance();
			engine.setRequestIssuer(authnRequest.getIssuer());
			String metadataUrl=idpProperties==null?null:idpProperties.getProperty(Constants.IDP_METADATA_URL);
			if(metadataUrl!=null && !metadataUrl.isEmpty()) {
				samlTokenFail.setIssuer(metadataUrl);
			}
			if(callback==null){
				authnRequest.setAssertionConsumerServiceURL(MetadataUtil.getAssertionUrlFromMetadata(new IdPMetadataProcessor(), engine, authnRequest));
				callback=authnRequest.getAssertionConsumerServiceURL();
			}
			samlTokenFail.setAssuranceLevel(eidasLoa);
			samlTokenFail = engine.generateEIDASAuthnResponseFail(authnRequest, samlTokenFail, request.getRemoteAddr(), false);
		} catch (Exception e) {
			throw new InternalErrorEIDASException("0", "Error generating SAMLToken");
		}
		this.samlToken = EIDASUtil.encodeSAMLToken(samlTokenFail.getTokenSaml());
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
