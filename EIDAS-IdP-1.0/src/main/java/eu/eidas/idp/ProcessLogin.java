package eu.eidas.idp;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.collect.ImmutableSet;
import com.ibm.icu.text.Transliterator;

import org.apache.log4j.Logger;

import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EIDASSubStatusCode;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.EidasErrors;
import eu.eidas.auth.commons.EidasParameterKeys;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeValue;
import eu.eidas.auth.commons.attribute.AttributeValueMarshaller;
import eu.eidas.auth.commons.attribute.AttributeValueMarshallingException;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.IResponseMessage;
import eu.eidas.auth.commons.protocol.eidas.IEidasAuthenticationRequest;
import eu.eidas.auth.commons.protocol.eidas.impl.EidasAuthenticationRequest;
import eu.eidas.auth.commons.protocol.impl.AuthenticationResponse;
import eu.eidas.auth.engine.ProtocolEngineFactory;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.auth.engine.metadata.MetadataSignerI;
import eu.eidas.auth.engine.metadata.MetadataUtil;
import eu.eidas.auth.engine.xml.opensaml.SAMLEngineUtils;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

public class ProcessLogin {

    private static final Logger logger = Logger.getLogger(ProcessLogin.class.getName());

    private static final String SIGN_ASSERTION_PARAM = "signAssertion";

    private String samlToken;

    private String username;

    private String callback;

    private String signAssertion;

    private String encryptAssertion;

    private String eidasLoa;

    private Properties idpProperties = EIDASUtil.loadConfigs(Constants.IDP_PROPERTIES);

    private final IdpMetadataFetcher idpMetadataFetcher = new IdpMetadataFetcher();

    private Properties loadConfigs(String path) {
        return EIDASUtil.loadConfigs(path);
    }

    private static final String TRANLITERATOR_ID = "Latin; NFD; [:Nonspacing Mark:] Remove; NFC;";

    private static Transliterator T = Transliterator.getInstance(TRANLITERATOR_ID);

    public static String transliterate(String value) {
        return T == null ? value : T.transliterate(value);
    }

    static CharsetEncoder encoder = Charset.forName("ISO-8859-1").newEncoder();

    public static boolean needsTransliteration(String v) {
        return !encoder.canEncode(v);
    }

    public static List<String> getValuesOfAttribute(String attrName, String value) {
        logger.trace("[processAuthentication] Setting: " + attrName + "=>" + value);
        ArrayList<String> tmp = new ArrayList<String>();
        tmp.add(value);
        if (needsTransliteration(value)) {
            String trValue = transliterate(value);
            tmp.add(trValue);
            logger.trace("[processAuthentication] Setting transliterated: " + attrName + "=>" + trValue);
        }
        return tmp;
    }

    public boolean processAuthentication(HttpServletRequest request, HttpServletResponse response) {

        EIDASUtil.createInstance(loadConfigs("eidasUtil.properties"));

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String samlToken = request.getParameter("samlToken");
        encryptAssertion = request.getParameter("encryptAssertion");
        eidasLoa = request.getParameter("eidasloa");

        IAuthenticationRequest authnRequest = validateRequest(samlToken);
        this.callback = authnRequest.getAssertionConsumerServiceURL();

        if (username == null || password == null) {
            sendErrorRedirect(authnRequest, request, EIDASSubStatusCode.AUTHN_FAILED_URI,
                              EidasErrorKey.AUTHENTICATION_FAILED_ERROR.toString());
            return false;
        }

        Properties users = null;
        String pass = null;
        try {
            users = loadConfigs("user.properties");
            pass = users.getProperty(username);
        } catch (SecurityEIDASException e) {
            sendErrorRedirect(authnRequest, request, EIDASSubStatusCode.AUTHN_FAILED_URI,
                              EidasErrorKey.AUTHENTICATION_FAILED_ERROR.toString());
        }

        if (pass == null || (!pass.equals(password))) {
            sendErrorRedirect(authnRequest, request, EIDASSubStatusCode.AUTHN_FAILED_URI,
                              EidasErrorKey.AUTHENTICATION_FAILED_ERROR.toString());
            return false;
        }

        this.username = username;

        ImmutableAttributeMap recvAttrMap = authnRequest.getRequestedAttributes();
        ImmutableAttributeMap sendAttrMap;
        ImmutableAttributeMap.Builder mapBuilder = ImmutableAttributeMap.builder();

        for (AttributeDefinition<?> attr : recvAttrMap.getDefinitions()) {
            String attrName = attr.getNameUri().toASCIIString();
            //lookup in properties file
            String key = username + "." + attrName.replaceFirst("[Hh][Tt][Tt][Pp]://", "");
            String value = users.getProperty(key);
            ArrayList<String> values = new ArrayList<String>();
            if (value != null && !value.isEmpty()) {
                values.addAll(getValuesOfAttribute(attrName, value));
            } else {
                String multivalues = users.getProperty(key + ".multivalue");
                if (null != multivalues && "true".equalsIgnoreCase(multivalues)) {
                    for (int i = 1; null != users.getProperty(key + "." + i); i++) {
                        values.addAll(getValuesOfAttribute(attrName, users.getProperty(key + "." + i)));
                    }
                }
            }
            if (!values.isEmpty()) {
                AttributeValueMarshaller<?> attributeValueMarshaller = attr.getAttributeValueMarshaller();
                ImmutableSet.Builder<AttributeValue<?>> builder = ImmutableSet.builder();
                for (final String val : values) {
                    AttributeValue<?> attributeValue = null;
                    try {
                        attributeValue = attributeValueMarshaller.unmarshal(val, false);
                    } catch (AttributeValueMarshallingException e) {
                        throw new IllegalStateException(e);
                    }
                    builder.add(attributeValue);
                }
                mapBuilder.put((AttributeDefinition) attr, (ImmutableSet) builder.build());
            }
        }
        sendAttrMap = mapBuilder.build();
        sendRedirect(authnRequest, sendAttrMap, request);
        return true;
    }

    private IAuthenticationRequest validateRequest(String samlToken) {
        IAuthenticationRequest authnRequest;
        try {
            ProtocolEngineI engine = getSamlEngineInstance();
            authnRequest =
                    engine.unmarshallRequestAndValidate(EidasStringUtil.decodeBytesFromBase64(samlToken), getCountry());
        } catch (Exception e) {
            throw new InvalidParameterEIDASException(
                    EidasErrors.get(EidasErrorKey.COLLEAGUE_REQ_INVALID_SAML.errorCode()),
                    EidasErrors.get(EidasErrorKey.COLLEAGUE_REQ_INVALID_SAML.errorMessage()));
        }
        return authnRequest;
    }

    private String getCountry() {
        return idpProperties == null ? null : idpProperties.getProperty(Constants.IDP_COUNTRY);
    }

    private void sendRedirect(IAuthenticationRequest authnRequest,
                              ImmutableAttributeMap attrMap,
                              HttpServletRequest request) {
        try {
            String remoteAddress = request.getRemoteAddr();
            if (request.getHeader(EidasParameterKeys.HTTP_X_FORWARDED_FOR.toString()) != null) {
                remoteAddress = request.getHeader(EidasParameterKeys.HTTP_X_FORWARDED_FOR.toString());
            } else {
                if (request.getHeader(EidasParameterKeys.X_FORWARDED_FOR.toString()) != null) {
                    remoteAddress = request.getHeader(EidasParameterKeys.X_FORWARDED_FOR.toString());
                }
            }

            ProtocolEngineI engine = getSamlEngineInstance();
            AuthenticationResponse.Builder responseAuthReq = new AuthenticationResponse.Builder();

            responseAuthReq.attributes(attrMap);
            responseAuthReq.inResponseTo(authnRequest.getId());
            authnRequest = processRequestCallback(authnRequest, engine);
            String metadataUrl = idpProperties == null ? null : idpProperties.getProperty(Constants.IDP_METADATA_URL);
            if (metadataUrl != null && !metadataUrl.isEmpty()) {
                responseAuthReq.issuer(metadataUrl);
            }
            responseAuthReq.levelOfAssurance(eidasLoa);

            responseAuthReq.id(SAMLEngineUtils.generateNCName());
            responseAuthReq.statusCode(EIDASStatusCode.SUCCESS_URI.toString());

            AuthenticationResponse response = responseAuthReq.build();

            IResponseMessage responseMessage = null;
            try {
                responseMessage = engine.generateResponseMessage(authnRequest, response, Boolean.parseBoolean(
                        request.getParameter(SIGN_ASSERTION_PARAM)), remoteAddress);
                samlToken = EidasStringUtil.encodeToBase64(responseMessage.getMessageBytes());

            } catch (EIDASSAMLEngineException se) {
                if (se.getErrorDetail().startsWith("Unique Identifier not found:") || se.getErrorDetail()
                        .startsWith("No attribute values in response.")) {
                    // special IdP case when subject cannot be constructed due to missing unique identifier
                    sendErrorRedirect(authnRequest, request, EIDASSubStatusCode.INVALID_ATTR_NAME_VALUE_URI,
                                      EidasErrorKey.ATT_VERIFICATION_MANDATORY.toString());
                } else {
                    throw se;
                }
            }
        } catch (Exception ex) {
            throw new InternalErrorEIDASException("0", "Error generating SAMLToken", ex);
        }
    }

    private ProtocolEngineI getSamlEngineInstance() throws EIDASSAMLEngineException {
        // ProtocolEngine engine = IDPUtil.createSAMLEngine(Constants.SAMLENGINE_NAME);
        return ProtocolEngineFactory.getDefaultProtocolEngine(Constants.SAMLENGINE_NAME);
    }

    private void sendErrorRedirect(IAuthenticationRequest authnRequest,
                                   HttpServletRequest request,
                                   EIDASSubStatusCode subStatusCode,
                                   String message) {
        byte[] failureBytes;
        try {
            AuthenticationResponse.Builder samlTokenFail = new AuthenticationResponse.Builder();
            samlTokenFail.statusCode(EIDASStatusCode.RESPONDER_URI.toString());
            samlTokenFail.subStatusCode(subStatusCode.toString());
            samlTokenFail.statusMessage(message);
            ProtocolEngineI engine = getSamlEngineInstance();
            samlTokenFail.id(SAMLEngineUtils.generateNCName());
            samlTokenFail.inResponseTo(authnRequest.getId());
            String metadataUrl = idpProperties == null ? null : idpProperties.getProperty(Constants.IDP_METADATA_URL);
            if (metadataUrl != null && !metadataUrl.isEmpty()) {
                samlTokenFail.issuer(metadataUrl);
            }
            authnRequest = processRequestCallback(authnRequest, engine);
            samlTokenFail.levelOfAssurance(eidasLoa);
            AuthenticationResponse token = samlTokenFail.build();
            IResponseMessage responseMessage =
                    engine.generateResponseErrorMessage(authnRequest, token, request.getRemoteAddr());
            failureBytes = responseMessage.getMessageBytes();
        } catch (Exception ex) {
            throw new InternalErrorEIDASException("0", "Error generating SAMLToken", ex);
        }
        this.samlToken = EidasStringUtil.encodeToBase64(failureBytes);
    }

    private IAuthenticationRequest processRequestCallback(IAuthenticationRequest authnRequest, ProtocolEngineI engine)
            throws EIDASSAMLEngineException {
        if (callback == null) {
            EidasAuthenticationRequest.Builder builder =
                    EidasAuthenticationRequest.builder((IEidasAuthenticationRequest) authnRequest);
            callback = MetadataUtil.getAssertionConsumerUrlFromMetadata(idpMetadataFetcher,
                                                                        (MetadataSignerI) engine.getSigner(),
                                                                        authnRequest);

            builder.assertionConsumerServiceURL(callback);
            authnRequest = builder.build();
        }
        return authnRequest;
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
