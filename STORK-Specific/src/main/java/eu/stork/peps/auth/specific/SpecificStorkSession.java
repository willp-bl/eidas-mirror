/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1 
 *  
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1); 
 * 
 * any use of this file implies acceptance of the conditions of this license. 
 * Unless required by applicable law or agreed to in writing, software distributed 
 * under the License is distributed on an "AS IS" BASIS,  WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the 
 * specific language governing permissions and    limitations under the License.
 */
package eu.stork.peps.auth.specific;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import eu.stork.peps.auth.commons.IStorkSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This interface is specific, each member state should modify this class to
 * implement the appropriate method of managing their sessions.
 *
 * @author ricardo.ferreira@multicert.com, renato.portela@multicert.com,
 *         luis.felix@multicert.com, hugo.magalhaes@multicert.com
 */
public class SpecificStorkSession extends LinkedHashMap<String, Object> implements IStorkSession {

    private static final Logger LOG = LoggerFactory.getLogger(SpecificStorkSession.class.getName());
    public SpecificStorkSession(){
        super();
    }
    /**
     * Unique identifier.
     */
    private static final long serialVersionUID = 3875683876999439349L;

    public void clear() {
        LOG.trace("SESSION clear (before clear)" + this.toString());
        super.clear();
    }

    public Object remove(Object key) {
        LOG.trace("SESSION Remove object (object key to remove " + key + ")");
        LOG.trace("(before remove)" + this.toString());
        return super.remove(key);
    }

    public Object put(String key, Object value){
        LOG.trace("SESSION put object (object key to put " + key + ")");
        LOG.trace("(before put)" + this.toString());
        return super.put(key, value);
    }

    /**
     * Session content representation in string
     * @return the values contained
     */
    public String toString(){
        StringBuilder stringBuilder = new StringBuilder("Session content (size ").append(this.size()).append(") - List of values : \n");
        for(Map.Entry<String, Object> entry : this.entrySet()) {
            Object val = entry.getValue();
            stringBuilder.append("- key : " ).append(entry.getKey()).append(" - value : ").append(val).append("\n");
        }
        return stringBuilder.toString();
    }
}
