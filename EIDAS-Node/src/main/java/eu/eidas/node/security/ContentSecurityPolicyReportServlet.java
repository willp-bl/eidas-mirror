/* 
#   Copyright (c) 2017 European Commission  
#   Licensed under the EUPL, Version 1.2 or – as soon they will be 
#   approved by the European Commission - subsequent versions of the 
#    EUPL (the "Licence"); 
#    You may not use this work except in compliance with the Licence. 
#    You may obtain a copy of the Licence at: 
#    * https://joinup.ec.europa.eu/page/eupl-text-11-12  
#    *
#    Unless required by applicable law or agreed to in writing, software 
#    distributed under the Licence is distributed on an "AS IS" basis, 
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#    See the Licence for the specific language governing permissions and limitations under the Licence.
 */
package eu.eidas.node.security;

import eu.eidas.node.AbstractNodeServlet;
import eu.eidas.node.logging.LoggingMarkerMDC;

import org.owasp.esapi.StringUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;

/**
 * @author mariger
 * @since on 12/11/2014.
 */
public class ContentSecurityPolicyReportServlet extends AbstractNodeServlet {
  private static final long serialVersionUID = -8979896410913801382L;

  /**
   * Logger object.
   */
  private static final Logger LOG = LoggerFactory.getLogger(ContentSecurityPolicyReportServlet.class.getName());

  @Override
  protected Logger getLogger() {
    return LOG;
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String line;
    try {
      setHTTPOnlyHeaderToSession(false, request, response);
      BufferedReader reader = request.getReader();
      while ((line=reader.readLine()) != null){
        if (StringUtilities.notNullOrEmpty(line,false)){
          LOG.info(LoggingMarkerMDC.SECURITY_WARNING, "BUSINESS EXCEPTION : Content security violation : " + line);
        }
      }
    } catch (IOException e) {
      LOG.error(e.getMessage()+" {}", e);
    }
  }
}
