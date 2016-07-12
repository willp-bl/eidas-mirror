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
package eu.stork.peps.speps;


import eu.stork.peps.auth.commons.IStorkSession;
import eu.stork.peps.auth.speps.ISPEPSService;
import eu.stork.peps.logging.LoggingMarkerMDC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class SPepsControllerService {

    private static final Logger LOG = LoggerFactory.getLogger(SPepsControllerService.class.getName());

    private String assertionConsUrl;

    /**
     * S-PEPS service.
     */
    private transient ISPEPSService spepsService;

    /**
     * Object that stores the session parameters.
     */
    private IStorkSession session;


    /**
     * URL of the S-PEPS authentication service.
     */
    private String pepsAuth;


  public String getAssertionConsUrl() {
        return assertionConsUrl;
    }

    public void setAssertionConsUrl(String assertionConsUrl) {
        this.assertionConsUrl = assertionConsUrl;
    }

    /**
     * Setter for spepsService.
     * @param sPEPSService The new spepsService value.
     * @see ISPEPSService
     */
    public void setSpepsService(final ISPEPSService sPEPSService) {
        this.spepsService = sPEPSService;
    }

    /**
     * Getter for spepsService.
     * @return The spepsService value.
     * @see ISPEPSService
     */
    public ISPEPSService getSpepsService() {
        return spepsService;
    }

    /**
     * Setter for the session object.
     * @param nSession The new session value.
     * @see IStorkSession
     */
    public void setSession(final IStorkSession nSession) {
        if (nSession != null){
            this.session = nSession;
        }
        LOG.info(LoggingMarkerMDC.SESSION_CONTENT, "SPEPS STORK-SESSION : setting a new session, size is " + this.session.size());
    }

    /**
     * Getter for the session object.
     *
     * @return The session object.
     *
     * @see IStorkSession
     */
    public IStorkSession getSession() {
        return session;
    }


    /**
     * Setter for pepsAuth.
     *
     * @param spepsAuthURL The new pepsAuth value.
     */
    public void setPepsAuth(final String spepsAuthURL) {
      this.pepsAuth = spepsAuthURL;
    }

    /**
     * Getter for pepsAuth.
     *
     * @return The pepsAuth value.
     */
    public String getPepsAuth() {
      return pepsAuth;
    }

  @Override
    public String toString() {
        return "SPepsControllerService{" +
                ", assertionConsUrl='" + assertionConsUrl + '\'' +
                ", spepsService=" + spepsService +
                ", session=" + session +
                '}';
    }
}
