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
package eu.eidas.auth.commons;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.regex.Pattern;

import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASServiceException;
import eu.eidas.auth.commons.exceptions.InvalidParameterEIDASException;

import org.apache.commons.lang.StringUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.encoders.Base64;

import javax.servlet.http.HttpServletRequest;

/**
 * This class holds static helper methods.
 */
public final class EIDASUtil {

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(EIDASUtil.class.getName());

    /**
     * Configurations object.
     */
    private static Properties configs;

    /**
     * Max prefix.
     */
    private static final String MAX_PARAM_PREFIX = "max.";

    /**
     * Code prefix to get error code.
     */
    private static final String CODE_PARAM_SUFFIX = ".code";

    /**
     * param's size prefix to get max param size.
     */
    private static final String MAX_PARAM_SUFFIX = ".size";

    /**
     * Message prefix to get error message.
     */
    private static final String MSG_PARAM_SUFFIX = ".message";

    /**
     * Contains the package name used to detect whether an error needs to be sent from eIDAS Service
     */
    private static final String PACKAGE_NAME_EIDAS_SERVICE = "eu.eidas.node.service";

    /**
     * Private constructor. Prevents the class from being instantiated.
     */
    private EIDASUtil() {
        // empty constructor
    }

    /**
     * Creates a single instance of this class and sets the properties.
     *
     * @param nConfigs The set of available configurations.
     * @return The created EIDASUtil's class.
     */
    public static EIDASUtil createInstance(final Properties nConfigs) {
        if (nConfigs != null) {
            EIDASUtil.configs = nConfigs;
        }
        return new EIDASUtil();
    }

    /**
     * Getter for the Properties.
     *
     * @return configs The properties value.
     */
    public Properties getConfigs() {
        return configs;
    }

    /**
     * Setter for the Properties.
     *
     * @param nConfigs The new properties value.
     */
    public static void setConfigs(final Properties nConfigs) {
        if (nConfigs == null) {
            EIDASUtil.configs = loadConfigs("eidasUtil.properties");
        }else {
            EIDASUtil.configs = nConfigs;
        }
    }

    /**
     * Returns the identifier of some configuration given a set of configurations
     * and the corresponding configuration key.
     *
     * @param configKey The key that IDs some configuration.
     * @return The configuration String value.
     */
    public static String getConfig(final String configKey) {
        String propertyValue = null;
        if (configs != null) {
            propertyValue = configs.getProperty(configKey);
            if (StringUtils.isEmpty(propertyValue)) {
                LOG.warn("BUSINESS EXCEPTION : Invalid property-Key value is null or empty {}", configKey);
            }
        } else {
                LOG.warn("BUSINESS EXCEPTION : Configs not loaded - property-Key value is null or empty {} ", configKey);
                propertyValue = configKey;
        }
        return propertyValue;
    }

    /**
     * Validates the input paramValue identified by the paramName.
     *
     * @param paramName  The name of the parameter to validate.
     * @param paramValue The value of the parameter to validate.
     * @return true if the parameter is valid.
     */
    public static boolean isValidParameter(final String paramName,
                                           final String paramValue) {

        final String validationParam = EIDASUtil.getConfig(EIDASParameters.VALIDATION_ACTIVE.toString());
        boolean retVal = true;

        final String paramConf = MAX_PARAM_PREFIX + paramName + MAX_PARAM_SUFFIX;

        if (EIDASValues.TRUE.toString().equals(validationParam)) {
            final String paramSizeStr = EIDASUtil.getConfig(paramConf);
            // Checking if the parameter size exists and if it's numeric
            if (StringUtils.isNumeric(paramSizeStr)) {
                final int maxParamSize = Integer.parseInt(paramSizeStr);
                if (StringUtils.isEmpty(paramValue)
                        || (paramValue.length() > maxParamSize)) {
                    retVal = false;
                    LOG.info("ERROR : Invalid parameter [" + paramName + "] value " + paramValue);
                }
            } else {
                retVal = false;
                LOG.info("ERROR : Missing " + paramConf
                        + " configuration in the eidasUtils.properties configuration file");
            }
        }
        return retVal;
    }

    /**
     * Validates the Parameter and throws an exception if an error occurs. Throws
     * an InvalidParameterEIDASException runtime exception if the parameter is
     * invalid.
     *
     * @param className  The Class Name that invoked the method.
     * @param paramName  The name of the parameter to validate.
     * @param paramValue The value of the parameter to validate.
     */
    public static void validateParameter(final String className,
                                         final String paramName, final Object paramValue) {

        if (paramValue == null) {
            EIDASUtil.validateParameter(className, paramName, "");
        } else {
            EIDASUtil.validateParameter(className, paramName, paramValue.toString());
        }
    }

    /**
     * Validates the Parameters and throws an exception if an error occurs.
     *
     * @param className  The Class Name that invoked the method.
     * @param paramName  The name of the parameter to validate.
     * @param paramValue The value of the parameter to validate.
     */
    public static void validateParameter(final String className,
                                         final String paramName, final String paramValue) {

        EIDASUtil.validateParameter(className, paramName, paramValue,
                EIDASUtil.getErrorCode(paramName), EIDASUtil.getErrorMessage(paramName));
    }

    /**
     * Validates the Parameters and throws an exception if an error occurs.
     *
     * @param className  The Class Name that invoked the method.
     * @param paramName  The name of the parameter to validate.
     * @param paramValue The value of the parameter to validate.
     * @param error      The EIDASError to get error code and messages from configs.
     */
    public static void validateParameter(final String className,
                                         final String paramName, final String paramValue, final EIDASErrors error) {

        EIDASUtil.validateParameter(className, paramName, paramValue,
                EIDASUtil.getConfig(error.errorCode()),
                EIDASUtil.getConfig(error.errorMessage()));
    }

    /**
     * Validates the HTTP Parameter and throws an exception if an error occurs.
     * Throws an InvalidParameterEIDASException runtime exception if the parameter
     * is invalid.
     *
     * @param className    The Class Name that invoked the method.
     * @param paramName    The name of the parameter to validate.
     * @param paramValue   The value of the parameter to validate.
     * @param errorCode    The error code to include on the exception.
     * @param errorMessage The error message to include on the exception.
     */
    public static void validateParameter(final String className,
                                         final String paramName, final String paramValue, final String errorCode,
                                         final String errorMessage) {

        if (!isValidParameter(paramName, paramValue)) {
            LOG.warn("Invalid parameter [" + paramName + "] value found at " + className);
            if (className !=null && className.startsWith(PACKAGE_NAME_EIDAS_SERVICE)){
                throw new InvalidParameterEIDASServiceException(errorCode, errorMessage);
            } else {
                throw new InvalidParameterEIDASException(errorCode, errorMessage);
            }
        }
    }

    /**
     * Getter for the error code of some given error related to the input param.
     *
     * @param paramName The name of the parameter associated with the error.
     * @return The code of the error.
     */
    private static String getErrorCode(final String paramName) {
        return getConfig(paramName + CODE_PARAM_SUFFIX);
    }

    /**
     * Getter for the error message of some given error related to the input
     * parameter.
     *
     * @param paramName The name of the parameter associated with the message.
     * @return The message for the error.
     */
    private static String getErrorMessage(final String paramName) {
        return getConfig(paramName + MSG_PARAM_SUFFIX);
    }

    /**
     * {@link Base64} encodes the input samlToken parameter.
     *
     * @param samlToken the SAML Token to be encoded.
     * @return The Base64 String representing the samlToken.
     * @see Base64#encode
     */
    public static String encodeSAMLToken(final byte[] samlToken) {
        try {
            if(samlToken.length==0) {
                return "";
            }
            return new String(Base64.encode(samlToken), "UTF8");
        } catch (UnsupportedEncodingException e) {
            LOG.info(EIDASErrors.INTERNAL_ERROR.errorMessage(), e);
            return null;
        }
    }

    /**
     * Decodes the {@link Base64} String input parameter representing a samlToken.
     *
     * @param samlToken the SAML Token to be decoded.
     * @return The samlToken decoded bytes.
     * @see Base64#decode
     */
    public static byte[] decodeSAMLToken(final String samlToken) {
        return Base64.decode(samlToken);
    }

    private static final String DEFAULT_HASH_DIGEST_CLASS="org.bouncycastle.crypto.digests.SHA512Digest";
    /**
     * Hashes a SAML token. Throws an InternalErrorEIDASException runtime exception
     * if the Cryptographic Engine fails.
     *
     * @param samlToken the SAML Token to be hashed.
     * @return byte[] with the hashed SAML Token.
     */
    public static byte[] hashPersonalToken(final byte[] samlToken) {
        String className = EIDASUtil.getConfig(EIDASValues.HASH_DIGEST_CLASS.toString());
        return hashPersonalToken(samlToken, className);
    }
    public static byte[] hashPersonalToken(final byte[] samlToken, String className) {

        try {
            String hashClassName=className;
            if(null==hashClassName || hashClassName.isEmpty()){
                hashClassName=DEFAULT_HASH_DIGEST_CLASS;
            }
            final Digest digest =
                    (Digest) Class.forName(hashClassName).getConstructor()
                            .newInstance((Object[]) null);
            digest.update(samlToken, 0, samlToken.length);

            final int retLength = digest.getDigestSize();
            final byte[] ret = new byte[retLength];

            digest.doFinal(ret, 0);
            return ret;

        } catch (final Exception e) {
            // For all those exceptions that could be thrown, we always log it and
            // thrown an InternalErrorEIDASException.
            LOG.info(EIDASErrors.HASH_ERROR.errorMessage(), e);
            throw new InternalErrorEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.HASH_ERROR.errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.HASH_ERROR.errorMessage()), e);
        }
    }

    /**
     * Gets the Eidas error code in the error message if exists!
     *
     * @param errorMessage The message to get the error code if exists;
     * @return the error code if exists. Returns null otherwise.
     */
    public static String getEidasErrorCode(final String errorMessage) {
        if (StringUtils.isNotBlank(errorMessage)
                && errorMessage.indexOf(EIDASValues.ERROR_MESSAGE_SEP.toString()) >= 0) {
            final String[] msgSplitted =
                    errorMessage.split(EIDASValues.ERROR_MESSAGE_SEP.toString());
            if (msgSplitted.length == 2 && StringUtils.isNumeric(msgSplitted[0])) {
                return msgSplitted[0];
            }
        }
        return null;
    }

    /**
     * Gets the Eidas error message in the saml message if exists!
     *
     * @param errorMessage The message to get in the saml message if exists;
     * @return the error message if exists. Returns the original message
     *         otherwise.
     */
    public static String getEidasErrorMessage(final String errorMessage) {
        if (StringUtils.isNotBlank(errorMessage) && errorMessage.indexOf(EIDASValues.ERROR_MESSAGE_SEP.toString()) >= 0) {
            final String[] msgSplitted = errorMessage.split(EIDASValues.ERROR_MESSAGE_SEP.toString());
            if (msgSplitted.length == 2 && StringUtils.isNumeric(msgSplitted[0])) {
                return msgSplitted[1];
            }
        }
        return errorMessage;
    }
    public static Map<String, String> getHttpRequestParameters(String className, HttpServletRequest request) {
        final Map<String, String> httpParameters = new HashMap<String, String>();

        // iterate over the parameters
        for (final Object key : request.getParameterMap().keySet()) {
            final String parameterName = (String) key;
            httpParameters.put(parameterName, Encode.forHtmlAttribute(request.getParameter(parameterName)));
        }

        // get the remote address, if the address came from a proxy server
        // then get the original address rather than the proxy address
        String remoteAddr = request.getRemoteAddr();
        if (request.getHeader(EIDASParameters.HTTP_X_FORWARDED_FOR.toString()) == null) {
            if (request.getHeader(EIDASParameters.X_FORWARDED_FOR.toString()) != null) {
                remoteAddr = request.getHeader(EIDASParameters.X_FORWARDED_FOR.toString());
            }
        } else {
            remoteAddr = request.getHeader(EIDASParameters.HTTP_X_FORWARDED_FOR.toString());
        }

        final String remoteAddrCons = EIDASParameters.REMOTE_ADDR.toString();
        EIDASUtil.validateParameter(className, remoteAddrCons, remoteAddr);
        httpParameters.put(remoteAddrCons, remoteAddr);
        httpParameters.put(EIDASParameters.BINDING.toString(), request.getMethod());

        return httpParameters;
    }

    private static final String CLASSPATH_PREFIX="classpath:/";
    private static final String FILE_PREFIX="file:";
    /**
     * Loads the configuration file pointed by the given path.
     *
     * @param path            Path to the input file
     * @param logError        Whether to log the error or to silently ignore it
     *
     * @return property The loaded Properties
     *
     * @throws InternalErrorEIDASException
     *             if the configuration file could not be loaded.
     */
    public static Properties loadConfigs(String path, boolean logError) {
        Properties properties = new Properties();
        InputStream is=null;
        try {
            is=EIDASUtil.class.getClassLoader().getResourceAsStream(path);
            if(is==null) {
                is=indirectedProps(path);
            }
            if(is!=null) {
                properties.load(is);
            }
        } catch (IOException e) {
            if(logError) {
                LOG.error("An error occurs when trying to load configuration file: " + path, e);
                throw new InternalErrorEIDASException("5", "Internal server error on loading configurations", e);
            }
        }finally{
            if(is!=null){
                try{
                   is.close();
                }catch(IOException e){
                    if(logError) {
                        LOG.error("An error occurred when trying to close resource stream: ", e);
                    }
                }
            }
        }
        return properties;
    }

    private static InputStream indirectedProps(String path) throws IOException{
        Properties indirection = EIDASUtil.loadConfigs("configlocation.properties");
        String location=indirection.getProperty(path);
        InputStream is=null;
        if(location!=null){
            if(location.startsWith(CLASSPATH_PREFIX)){
                is=EIDASUtil.class.getClassLoader().getResourceAsStream(location.substring(CLASSPATH_PREFIX.length()));
            }else if(location.startsWith(FILE_PREFIX)){
                is=new FileInputStream(location.substring(FILE_PREFIX.length()));
            }
        }
        return is;
    }
    public static Properties loadConfigs(String path) {
        return loadConfigs(path, true);
    }

    /**
     *
     * @param values a string containing several chunks separated by ;
     * @return a set of chunks extracted from values
     */
    public static Set<String> parseSemicolonSeparatedList(String values){
        Pattern sepPattern = Pattern.compile(";");
        Set<String> result=new HashSet<String>();
        if(!StringUtils.isEmpty(values)) {
            String[] valuesArr = sepPattern.split(values);
            if (valuesArr != null) {
                for (String value : valuesArr) {
                    value = value.trim();
                    if(!StringUtils.isEmpty(value)) {
                    	result.add(value);
                    }
                }
            }
        }
        return result;
    }
}
