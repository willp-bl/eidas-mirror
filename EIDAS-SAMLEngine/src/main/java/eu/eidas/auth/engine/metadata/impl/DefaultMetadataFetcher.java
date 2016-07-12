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
package eu.eidas.auth.engine.metadata.impl;

import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.google.common.cache.CacheBuilder;

import org.opensaml.saml2.metadata.EntityDescriptor;

import eu.eidas.auth.engine.metadata.MetadataFetcherI;

/**
 * The default implementation of the {@link MetadataFetcherI} interface.
 * <p>
 * It uses a very simple in memory cache which expires after 15 minutes and can cache up to 100 metadata files.
 *
 * @since 1.1
 */
public class DefaultMetadataFetcher extends AbstractCachingMetadataFetcher {

    private final ConcurrentMap<String, EntityDescriptor> map = CacheBuilder.newBuilder()
            .expireAfterAccess(15L, TimeUnit.MINUTES)
            .maximumSize(100L).<String, EntityDescriptor>build().asMap();

    @Nullable
    @Override
    protected EntityDescriptor getFromCache(@Nonnull String url) {
        return map.get(url);
    }

    @Override
    protected void putInCache(@Nonnull String url, @Nonnull EntityDescriptor entityDescriptor) {
        map.put(url, entityDescriptor);
    }

    @Override
    protected void removeFromCache(@Nonnull String url) {
        map.remove(url);
    }
}
