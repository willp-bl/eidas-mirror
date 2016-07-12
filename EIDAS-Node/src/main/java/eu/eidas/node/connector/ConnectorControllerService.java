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
package eu.eidas.node.connector;


import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.node.auth.connector.ICONNECTORService;
import eu.eidas.node.logging.LoggingMarkerMDC;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ConnectorControllerService {

    private static final Logger LOG = LoggerFactory.getLogger(ConnectorControllerService.class.getName());

    private String assertionConsUrl;

    /**
     * Connector service.
     */
    private transient ICONNECTORService connectorService;

    /**
     * Object that stores the session parameters.
     */
    private IEIDASSession session;


    /**
     * URL of the Connector authentication service.
     */
    private String nodeAuth;


  public String getAssertionConsUrl() {
        return assertionConsUrl;
    }

    public void setAssertionConsUrl(String assertionConsUrl) {
        this.assertionConsUrl = assertionConsUrl;
    }

    /**
     * Setter for connectorService.
     * @param connectorService The new connectorService value.
     * @see ICONNECTORService
     */
    public void setConnectorService(final ICONNECTORService connectorService) {
        this.connectorService = connectorService;
    }

    /**
     * Getter for connectorService.
     * @return The connectorService value.
     * @see ICONNECTORService
     */
    public ICONNECTORService getConnectorService() {
        return connectorService;
    }

    /**
     * Setter for the session object.
     * @param nSession The new session value.
     * @see IEIDASSession
     */
    public void setSession(final IEIDASSession nSession) {
        if (nSession != null){
            this.session = nSession;
        }
        LOG.info(LoggingMarkerMDC.SESSION_CONTENT, "Connector EIDAS-SESSION : setting a new session, size is " + this.session.size());
    }

    /**
     * Getter for the session object.
     *
     * @return The session object.
     *
     * @see IEIDASSession
     */
    public IEIDASSession getSession() {
        return session;
    }


    /**
     * Setter for nodeAuth.
     *
     * @param nodeAuth The new nodeAuth value.
     */
    public void setNodeAuth(final String nodeAuth) {
      this.nodeAuth = nodeAuth;
    }

    /**
     * Getter for nodeAuth.
     *
     * @return The nodeAuth value.
     */
    public String getNodeAuth() {
      return nodeAuth;
    }

  @Override
    public String toString() {
        return "ConnectorControllerService{" +
                ", assertionConsUrl='" + assertionConsUrl + '\'' +
                ", connectorService=" + connectorService +
                ", session=" + session +
                '}';
    }
}
