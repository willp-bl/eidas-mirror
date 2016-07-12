package eu.stork.peps.security;

import eu.stork.peps.logging.LoggingMarkerMDC;
import eu.stork.peps.utils.CountrySpecificUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
public class ContentSecurityPolicyFilter extends AbstractSecurityResponseHeader implements Filter {
    /**
     * Logger object.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ContentSecurityPolicyFilter.class.getName());

    /**
     * Used to prepare (one time for all) set of CSP policies that will be applied on each HTTP response.
     *
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    @Override
    public void init(FilterConfig fConfig) throws ServletException {
        LOGGER.info(LoggingMarkerMDC.SYSTEM_EVENT, "Init of CSP filter");
        super.init();
    }

    private boolean shouldDisableFilter(HttpServletRequest httpRequest){
        return CountrySpecificUtil.isRequestAllowed(httpRequest);
    }
    /**
     * Add CSP policies on each HTTP response.
     *
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain fchain) throws IOException, ServletException {
        try {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        LOGGER.trace("ContentSecurityPolicy FILTER for " + httpRequest.getServletPath());
        if ( shouldDisableFilter(httpRequest)){
            LOGGER.info("Redirecting to country plugin : no csp defined");
        } else {
            if (configurationSecurityBean.getIsContentSecurityPolicyActive()) {
                processContentSecurityPolicy(httpRequest, httpResponse);
            }

            if (configurationSecurityBean.isIncludeXXssProtection()){
                httpResponse.setHeader(X_XSS_PROTECTION_HEADER, X_XSS_PROTECTION_MODE_BLOCK);
            }
            if (configurationSecurityBean.isIncludeXContentTypeOptions()){
                httpResponse.setHeader(X_CONTENT_TYPE_OPTIONS_HEADER, X_CONTENT_TYPE_OPTIONS_NO_SNIFF);
            }
            if (configurationSecurityBean.isIncludeXFrameOptions()){
                httpResponse.setHeader(X_FRAME_OPTIONS_HEADER, X_FRAME_OPTIONS_SAME_ORIGIN);
            }
            if (configurationSecurityBean.isIncludeHSTS()){
                httpResponse.setHeader(STRICT_TRANSPORT_SECURITY_HEADER, STRICT_TRANSPORT_SECURITY);
            }

            httpResponse.setHeader(HTTP_1_1_CACHE_CONTROL, HTTP_1_1_CACHE_CONTROL_NOCACHE); // HTTP 1.1.
            httpResponse.setHeader(HTTP_1_0_PRAGMA, HTTP_1_0_PRAGMA_NOCACHE); // HTTP 1.0.
            httpResponse.setHeader(PROXIES_EXPIRES, PROXIES_EXPIRES_0); // Proxies.
        }

        fchain.doFilter(request, response);
        }catch(Exception e){
            LOGGER.info("ERROR : ", e.getMessage());
            LOGGER.debug("ERROR : ", e);
            throw new ServletException(e);
        }
    }

    @Override
    public void destroy() {
        LOGGER.info(LoggingMarkerMDC.SYSTEM_EVENT, "Destroy of CSP filter");
    }
}
