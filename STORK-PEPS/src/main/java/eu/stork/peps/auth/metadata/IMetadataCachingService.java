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
package eu.stork.peps.auth.metadata;

import org.opensaml.saml2.metadata.EntityDescriptor;

/**
 * provides caching services for SAML metadata entity descriptors
 */
public interface IMetadataCachingService {
    /**
     *
     * @param url
     * @return the descriptor (stored in the cache) associated with url
     */
    EntityDescriptor getDescriptor(String url);
    /**
     *
     * @param url
     * @return the descriptor type of the descriptor (stored in the cache) associated with url
     */
    EntityDescriptorType getDescriptorType(String url);

    /**
     * add a descriptor in the cache
     * @param url
     * @param ed
     * @param type - the type (origin) of the descriptor
     */
    void putDescriptor(String url, EntityDescriptor ed, EntityDescriptorType type);
}
