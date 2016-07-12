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

import eu.stork.peps.PepsBeanNames;
import eu.stork.peps.utils.PEPSMetadataGenerator;
import eu.stork.peps.utils.PropertiesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * generates metadata used to communicate with the SPEPS.
 */
public class SPepsMetadataGeneratorServlet extends AbstractSPepsServlet{
    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SPepsMetadataGeneratorServlet.class.getName());
    private static final String IDP_METADATA_URL="/SPEPSResponderMetadata";

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    //SPEPS presents itself as either an IdP or a SP
    //IdP: will use SP-SPEPS SAMLEngine (since it is an IdP for a SP)
    //SP: will use SPEPS-CPEPS SAMLEngine

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String generatorName=request.getServletPath().startsWith(IDP_METADATA_URL)?PepsBeanNames.CONNECTOR_AS_IDP_METADATA_GENERATOR.toString():PepsBeanNames.CONNECTOR_METADATA_GENERATOR.toString();
        PEPSMetadataGenerator generator = (PEPSMetadataGenerator)getApplicationContext().getBean(generatorName);
        PropertiesUtil.checkSPEPSActive();
        if(PropertiesUtil.isMetadataEnabled()) {
            response.getOutputStream().print(generator.generateSPEPSMetadata());
        }else{
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }
}
