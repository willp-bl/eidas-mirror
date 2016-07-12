/*
 * Copyright (c) 2015 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the Licence is distributed on an "AS IS" basis,
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

package eu.eidas.node;

import eu.eidas.auth.commons.EIDASParameters;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EIDASValues;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.MDC;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;


public abstract class AbstractSpecificServlet extends HttpServlet {
    private static final long serialVersionUID = -1223043917139819408L;

    /*Dedicated marker for the web events*/
    public static final Marker WEB_EVENT = MarkerFactory.getMarker("WEB_EVENT");
    public static final String MDC_SESSIONID = "sessionId";
    public static final String MDC_REMOTE_HOST = "remoteHost";

    abstract protected Logger getLogger();

    /**
     * Obtaining the application context
     *
     * @return applicationContext
     */
    protected ApplicationContext getApplicationContext() {
        return WebApplicationContextUtils.getWebApplicationContext(getServletContext());
    }

    /**
     * Encodes any given URL.
     *
     * @param url      The URL to be encoded.
     * @param request
     * @param response @return The encoded URL.
     */
    protected final String encodeURL(final String url, HttpServletRequest request, HttpServletResponse response) {

        if (request.getSession(false) == null) {
            // If the session doesn't exist, then we must create it.
            request.getSession();
        }
        return response.encodeURL(url);
    }

    /**
     * Sets HTTPOnly Header to prevent cookies from being accessed through
     * client-side script.
     */
    protected final void setHTTPOnlyHeader(HttpServletRequest request, HttpServletResponse response) {

        if (request.getSession() == null || request.getSession(false) == null) {
            // If the session doesn't exist, then we must create it.
            request.getSession();
            // We will set the value only if we didn't set it already.
            if (!response.containsHeader(EIDASValues.SETCOOKIE.toString())) {
                response.setHeader(EIDASValues.SETCOOKIE.toString(),
                        createHttpOnlyCookie(request));
            }
        }
    }

    /**
     * Creates the HttpOnly cookie string.
     *
     * @param request
     * @return The HttpOnly cookie.
     */
    private String createHttpOnlyCookie(HttpServletRequest request) {
        final StringBuilder strBuf = new StringBuilder();
        strBuf.append(EIDASValues.JSSESSION.toString());
        strBuf.append(EIDASValues.EQUAL.toString());
        strBuf.append(request.getSession().getId());
        strBuf.append(EIDASValues.SEMICOLON.toString());
        strBuf.append(EIDASValues.SPACE.toString());
        strBuf.append(EIDASValues.HTTP_ONLY.toString());
        return strBuf.toString();
    }

    /**
     * Creates a {@link java.util.Map} with all the parameters from the servletRequest, plus
     * the Remote Address, Remote Host, Local Address and Local Host. Then returns
     * the map.
     *
     * @return A map with the servletRequest's parameters, both the remote and
     * local addresses and the remote and local host.
     * @see java.util.Map
     */
    protected final Map<String, Object> getHttpRequestParameters(HttpServletRequest request) {

        final Map<String, Object> httpParameters = new HashMap<String, Object>();

        // iterate over the parameters
        for (final Object key : request.getParameterMap().keySet()) {
            final String parameterName = (String) key;
            httpParameters.put(parameterName, request.getParameter(parameterName));
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
        EIDASUtil.validateParameter(this.getClass().getCanonicalName(), remoteAddrCons, remoteAddr);
        httpParameters.put(remoteAddrCons, remoteAddr);

        return httpParameters;
    }

    /**
     * Creates a {@link Map} with all the attributes and headers from the
     * servletRequest and then returns it.
     *
     * @param request
     * @return A map with the servletRequest's attributes.
     * @see Map
     */
    @SuppressWarnings("unchecked")
    protected final Map<String, Object> getHttpRequestAttributesHeaders(HttpServletRequest request) {

        final Map<String, Object> reqAttrHeaders = new HashMap<String, Object>();
        // Store servletRequest's attributes
        final Enumeration<String> attibuteNames = request.getAttributeNames();
        while (attibuteNames.hasMoreElements()) {
            final String attrName = attibuteNames.nextElement();
            getLogger().trace("getHttpRequestAttributesHeader name {} val {} ", attrName, request.getAttribute(attrName));
            if (request.getAttribute(attrName) != null) {
                reqAttrHeaders.put(attrName, request.getAttribute(attrName));
            }
        }

        // Store servletRequest's headers
        final Enumeration<String> headerNames =
                request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            final String headerName = headerNames.nextElement();
            if (request.getHeader(headerName) != null) {
                reqAttrHeaders.put(headerName, request.getHeader(headerName));
            }
        }
        return reqAttrHeaders;
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (!StringUtils.isEmpty(request.getRemoteHost())) {
            MDC.put(MDC_REMOTE_HOST, request.getRemoteHost());
        }
        MDC.put(MDC_SESSIONID, request.getSession().getId());
        getLogger().info(WEB_EVENT, "**** CALL to servlet " + this.getClass().getName()
                + "FROM " + request.getRemoteAddr()
                + "HTTP " + request.getMethod()
                + " SESSIONID " + request.getSession().getId() + "****");

        super.service(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        getLogger().warn(WEB_EVENT, "GET method invocation : possible spidering");
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        getLogger().warn(WEB_EVENT, "HEAD method invocation : possible spidering");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        getLogger().warn(WEB_EVENT, "POST method invocation : possible spidering");
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        getLogger().warn(WEB_EVENT, "DELETE method invocation : possible spidering");
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        getLogger().warn(WEB_EVENT, "PUT method invocation : possible spidering");
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        getLogger().warn(WEB_EVENT, "OPTIONS method invocation : possible spidering");
    }

    @Override
    protected void doTrace(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        getLogger().warn(WEB_EVENT, "TRACE method invocation : possible spidering");
    }
}
