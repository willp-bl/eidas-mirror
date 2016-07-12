package eu.eidas.sp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.opensymphony.xwork2.Action;
import com.opensymphony.xwork2.ActionSupport;

import org.apache.commons.lang.StringUtils;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeValue;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.protocol.IAuthenticationResponse;
import eu.eidas.auth.engine.ProtocolEngineFactory;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.encryption.exception.UnmarshallException;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

import static eu.eidas.sp.Constants.SP_CONF;

/**
 * This Action recives a SAML Response, shows it to the user and then validates it getting the attributes values
 *
 * @author iinigo
 */
public class ReturnAction extends ActionSupport implements ServletRequestAware, ServletResponseAware {

    private static final long serialVersionUID = 3660074009157921579L;

    private static final String SAML_VALIDATION_ERROR = "Could not validate token for Saml Response";

    static final Logger logger = LoggerFactory.getLogger(IndexAction.class.getName());

    private String SAMLResponse;

    private String samlResponseXML;

    private String samlUnencryptedResponseXML;

    private ImmutableMap<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> attrMap;

    private HttpServletRequest request;

    private Properties configs;

    private String providerName;
    //private static String spUrl;

    /**
     * Translates the SAMLResponse to XML format in order to be shown in the JSP
     *
     * @return
     */
    public String execute() {

        configs = SPUtil.loadSPConfigs();

        providerName = configs.getProperty(Constants.PROVIDER_NAME);

        byte[] decSamlToken = EidasStringUtil.decodeBytesFromBase64(SAMLResponse);
        samlResponseXML = EidasStringUtil.toString(decSamlToken);
        try {
            SpProtocolEngineI engine = SpProtocolEngineFactory.getSpProtocolEngine(SP_CONF);
            //validate SAML Token
            IAuthenticationResponse response =
                    engine.unmarshallResponseAndValidate(decSamlToken, request.getRemoteHost(), 0, null);

            boolean encryptedResponse = SPUtil.isEncryptedSamlResponse(decSamlToken);
            if (encryptedResponse) {
                byte[] eidasTokenSAML = engine.checkAndDecryptResponse(decSamlToken);
                samlUnencryptedResponseXML = SPUtil.extractAssertionAsString(EidasStringUtil.toString(eidasTokenSAML));
            }

        } catch (UnmarshallException e) {
            logger.error(e.getMessage(), e);
            throw new ApplicationSpecificServiceException(SAML_VALIDATION_ERROR, e.getMessage());
        } catch (EIDASSAMLEngineException e) {
            logger.error(e.getMessage(), e);
            if (StringUtils.isEmpty(e.getErrorDetail())) {
                throw new ApplicationSpecificServiceException(SAML_VALIDATION_ERROR, e.getErrorMessage());
            } else {
                throw new ApplicationSpecificServiceException(SAML_VALIDATION_ERROR, e.getErrorDetail());
            }
        }

        return Action.SUCCESS;
    }

    /**
     * Validates the request and displays the value of the requested attributes
     *
     * @return
     */
    public String populate() {

        IAuthenticationResponse authnResponse;
        ImmutableAttributeMap personalAttributeList = null;

        //spUrl = configs.getProperty(Constants.SP_URL);

        //Decodes SAML Response
        byte[] decSamlToken = EidasStringUtil.decodeBytesFromBase64(SAMLResponse);

        //Get SAMLEngine instance

        try {
            ProtocolEngineI engine = ProtocolEngineFactory.getDefaultProtocolEngine(SP_CONF);
            //validate SAML Token
            authnResponse = engine.unmarshallResponseAndValidate(decSamlToken, request.getRemoteHost(), 0, null);

        } catch (EIDASSAMLEngineException e) {
            logger.error(e.getMessage());
            if (StringUtils.isEmpty(e.getErrorDetail())) {
                throw new ApplicationSpecificServiceException(SAML_VALIDATION_ERROR, e.getErrorMessage());
            } else {
                throw new ApplicationSpecificServiceException(SAML_VALIDATION_ERROR, e.getErrorDetail());
            }
        }

        if (authnResponse.isFailure()) {
            throw new ApplicationSpecificServiceException("Saml Response is fail", authnResponse.getStatusMessage());
        } else {
            attrMap = authnResponse.getAttributes().getAttributeMap();//= new HashMap<AttributeDefinition<?>, List<String>>();
            return "populate";
        }
    }

    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }

    public void setServletResponse(HttpServletResponse response) {
    }

    public void setAttrMap( ImmutableMap<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> attrMap) {
        this.attrMap = attrMap;
    }

    public  ImmutableMap<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> getAttrMap() {
        return attrMap;
    }

    public String getProviderName() {
        return providerName;
    }

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

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

    public String getSamlUnencryptedResponseXML() {
        return samlUnencryptedResponseXML;
    }

    public void setSamlUnencryptedResponseXML(String samlUnencryptedResponseXML) {
        this.samlUnencryptedResponseXML = samlUnencryptedResponseXML;
    }
}