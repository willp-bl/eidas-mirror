package eu.stork.peps.security;

import eu.stork.peps.ApplicationContextProvider;
import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.logging.LoggingMarkerMDC;
import eu.stork.peps.utils.CountrySpecificUtil;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.context.ApplicationContext;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * This filter set CSP policies using all HTTP headers defined into W3C specification.<br/>
 *
 * Purposes :
 *
 * XSS countermeasures :
 *   1. Content Security Policy (CSP)
 *      Sample generated : X-Content-Security-Policy:default-src 'none'; object-src 'self'; style-src 'self'; img-src 'self'; xhr-src 'self'; connect-src 'self';script-src 'self'; report-uri http://peps:8080/PEPS/cspReportHandler
 *    - X-Content-Security-Policy for backward compatibility
 *    - X-WebKit-CSP for backward compatibility
 *    - Content-Security-Policy
 *    - Report handler logging all the CSP violations
 *   2. X-XSS-Protection header
 *   3. X-Content-Type-Options: nosniff
 * Click-jacking countermeasures :
 *  X-Frame-Options header
 *
 * @author vanegdi
 * @since 1.2.0
 */
public abstract class AbstractSecurityResponseHeader {

    /**
     * Logger object.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractSecurityResponseHeader.class.getName());

    protected static final String CONTENT_SECURITY_POLICY_HEADER      = "Content-Security-Policy";
    protected static final String X_CONTENT_SECURITY_POLICY_HEADER    = "X-Content-Security-Policy";
    protected static final String X_WEB_KIT_CSP_HEADER                = "X-WebKit-CSP";
    protected static final String X_XSS_PROTECTION_HEADER             = "X-XSS-Protection";
    protected static final String X_CONTENT_TYPE_OPTIONS_HEADER       = "X-Content-Type-Options";
    protected static final String X_FRAME_OPTIONS_HEADER              = "X-Frame-Options";
    protected static final String STRICT_TRANSPORT_SECURITY_HEADER    = "Strict-Transport-Security";

    protected static final String SELF_ORIGIN_LOCATION_REF            = "'self'";
    protected static final String X_FRAME_OPTIONS_SAME_ORIGIN         = "SAMEORIGIN";
    protected static final String X_CONTENT_TYPE_OPTIONS_NO_SNIFF     = "nosniff";
    protected static final String X_XSS_PROTECTION_MODE_BLOCK         = "1; mode=block";
    protected static final String STRICT_TRANSPORT_SECURITY           = "max-age=600000; includeSubdomains"; // 10 minutes

    protected static final String HTTP_1_1_CACHE_CONTROL              = "Cache-Control";
    protected static final String HTTP_1_1_CACHE_CONTROL_NOCACHE      = "no-cache, no-store, max-age=0, must-revalidate, private";
    protected static final String HTTP_1_0_PRAGMA                     = "Pragma";
    protected static final String HTTP_1_0_PRAGMA_NOCACHE             = "no-cache";
    protected static final String PROXIES_EXPIRES                     = "Expires";
    protected static final String PROXIES_EXPIRES_0                   = "0";

    private static final int HEX_CONVERT_SHIFT = 4;
    public static final int INT_OXFO    = 0xF0;
    public static final int INT_OXF     = 0x0F;

    //Contains the security configuration
    protected ConfigurationSecurityBean configurationSecurityBean;

    /**
     * Configuration member to specify if web app use web fonts
     */
    protected static final boolean APP_USE_WEBFONTS           = false;
    /**
     * Configuration member to specify if web app use videos or audios
     */
    protected static final boolean APP_USE_AUDIOS_OR_VIDEOS   = false;

    /**
     * List CSP HTTP Headers
     */
    protected List<String> cspHeaders = new ArrayList<String>();

    /**
     * Collection of CSP polcies that will be applied
     */
    protected String policies = null;

    /**
     * Used for Script Nonce
     */
    protected SecureRandom secureRandom = null;

    static final char[] HEX_DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    protected static String encodeHexString (byte[] data, char[] toDigits){
        int l = data.length;
        char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++, j+=2) {
            out[j] = toDigits[(INT_OXFO & data[i]) >>> HEX_CONVERT_SHIFT];
            out[j+1] = toDigits[INT_OXF & data[i]];
        }
        return new String(out);
    }

    /**
     * Used to prepare (one time for all) set of CSP policies that will be applied on each HTTP response.
     */
    public void init() {
        LOGGER.debug("Init of contentSecurityPolicy FILTER");
        // Init secure random
        try {
            this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Error in filter init {}", e);
        }

        ApplicationContext context = ApplicationContextProvider.getApplicationContext();
        configurationSecurityBean = (ConfigurationSecurityBean) context.getBean(PepsBeanNames.SECURITY_CONFIG.toString());
        // Loading the specific country handler plugins to allow plugin dynamic load
        CountrySpecificUtil csu=context.getBean(CountrySpecificUtil.class);
        csu.loadCountryHandlers();


      // Define list of CSP HTTP Headers : used for reverse compatibility
        this.cspHeaders.add(CONTENT_SECURITY_POLICY_HEADER);
        this.cspHeaders.add(X_CONTENT_SECURITY_POLICY_HEADER);
        this.cspHeaders.add(X_WEB_KIT_CSP_HEADER);

        // Define CSP policies
        // Loading policies for Frame and Sandboxing will be dynamically defined : We need to know if context use Frame
        List<String> cspPolicies = new ArrayList<String>();

        // --Disable default source in order to avoid browser fallback loading using 'default-src' locations
        cspPolicies.add("default-src 'none'");

        // --Define loading policies for Plugins
        cspPolicies.add("object-src " + SELF_ORIGIN_LOCATION_REF);
        // --Define loading policies for Styles (CSS)
        cspPolicies.add("style-src " + SELF_ORIGIN_LOCATION_REF);
        // --Define loading policies for Images
        cspPolicies.add("img-src " + SELF_ORIGIN_LOCATION_REF);
        // --Define loading policies for Form
        if (configurationSecurityBean.isIncludeMozillaDirectives()) {
            cspPolicies.add("xhr-src 'self'");
        }
        // --Define loading policies for Audios/Videos
        if (APP_USE_AUDIOS_OR_VIDEOS) {
            cspPolicies.add("media-src " + SELF_ORIGIN_LOCATION_REF);
        }
        // --Define loading policies for Fonts
        if (APP_USE_WEBFONTS) {
            cspPolicies.add("font-src " + SELF_ORIGIN_LOCATION_REF);
        }
        // --Define loading policies for Connection
        cspPolicies.add("connect-src " + SELF_ORIGIN_LOCATION_REF);

        // Target formating
        this.policies = cspPolicies.toString().replaceAll("(\\[|\\])", "").replaceAll(",", ";").trim();
        LOGGER.trace("contentSecurityPolicy Config - ContentSecurityPolicyActive {} - moaActive {} - includeXSSProtection {} - includeHSTS {} - XContentTypeOptions {} - includeMozillaDirectives {} - includeXFrameOptions {}",
                configurationSecurityBean.getIsContentSecurityPolicyActive(),
                configurationSecurityBean.getIsMoaActive(),
                configurationSecurityBean.isIncludeXXssProtection(),
                configurationSecurityBean.isIncludeHSTS(),
                configurationSecurityBean.isIncludeXContentTypeOptions(),
                configurationSecurityBean.isIncludeMozillaDirectives(),
                configurationSecurityBean.isIncludeXFrameOptions());
    }

    /**
     * Method used to process the content security policy header
     * @param httpRequest request
     * @param httpResponse response
     * @throws javax.servlet.ServletException
     */
    protected void processContentSecurityPolicy(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException {
        if (!StringUtils.isEmpty(httpRequest.getRemoteHost())) {
            MDC.put(LoggingMarkerMDC.MDC_REMOTE_HOST, httpRequest.getRemoteHost());
        }
    /* Add CSP policies to HTTP response */
        StringBuilder policiesBuffer = new StringBuilder(this.policies);
        policiesBuffer.append(";").append("script-src " + SELF_ORIGIN_LOCATION_REF);
        //policiesBuffer.append(";").append("script-src 'self' 'unsafe-inline'" );

        // Add Script Nonce CSP Policy
        // --Generate a random number
        String randomNum = Integer.toString(this.secureRandom.nextInt());
        // --Get its digest
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException(e);
        }
        byte[] digest = sha.digest(randomNum.getBytes(Charset.forName("UTF-8")));
        // --Encode it into HEXA
        String scriptNonce = encodeHexString(digest, HEX_DIGITS_LOWER);
        policiesBuffer.append(";").append("script-nonce ").append(scriptNonce);
        policiesBuffer.append(";").append("report-uri ").append(httpRequest.getScheme()).append("://").append(httpRequest.getServerName()).append(":").append(httpRequest.getServerPort()).append(httpRequest.getContextPath()).append("/cspReportHandler");
        // --Made available script nonce in view app layer
        httpRequest.setAttribute("CSP_SCRIPT_NONCE", scriptNonce);

        // Add policies to all HTTP headers
        for (String header : this.cspHeaders) {
            httpResponse.setHeader(header, policiesBuffer.toString());
            LOGGER.trace("Adding policy to header - " + policiesBuffer.toString());
        }
    }
}
