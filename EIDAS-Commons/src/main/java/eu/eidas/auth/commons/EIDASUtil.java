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
package eu.eidas.auth.commons;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.util.Preconditions;

/**
 * Static helper methods.
 *
 * @deprecated This class has more than one responsibility and relies on a mutable static state with is setup in an
 * awkward way.
 */
@SuppressWarnings("ConstantConditions")
@Deprecated
public enum EIDASUtil {

    /**
     * Effective Java, 2nd Ed.: Item 3: Enforce the singleton property with an enum type.
     */
    INSTANCE;

    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(EIDASUtil.class);

    private static final Pattern SEMI_COLON_SEPARATOR_PATTERN = Pattern.compile(";");

    /**
     * Path and name of the EIDAS properties file.
     */
    private static final String EIDAS_UTIL_PROPERTIES = "eidasUtil.properties";

    /**
     * Path and name of the EIDAS configuration indirection properties file.
     */
    private static final String CONFIG_LOCATION_PROPERTIES = "configlocation.properties";

    /**
     * Configurations object.
     */
    private final AtomicReference<ImmutableMap<String, String>> propertiesRef;

    private static final String CLASSPATH_PREFIX = "classpath:/";

    private static final String FILE_PREFIX = "file:";

    /**
     * Private constructor. Prevents the class from being instantiated.
     */
    EIDASUtil() {
        propertiesRef = new AtomicReference<ImmutableMap<String, String>>(ImmutableMap.<String, String>of());
    }

    @SuppressWarnings("CollectionDeclaredAsConcreteClass")
    @Nonnull
    static ImmutableMap<String, String> immutableMap(@Nullable Properties properties) {
        if (null == properties || properties.isEmpty()) {
            return ImmutableMap.of();
        }
        return Maps.fromProperties(properties);
    }

    @Nonnull
    static Properties toProperties(@Nonnull ImmutableMap<String, String> immutableMap) {
        Properties properties = new Properties();
        //noinspection UseOfPropertiesAsHashtable
        properties.putAll(immutableMap);
        return properties;
    }

    /**
     * Sets the properties.
     *
     * @param properties The properties to set.
     * @return the singleton instance (same as {@link #INSTANCE}).
     * @deprecated This method is badly named, it only sets the properties to a new reference. Use {@link
     * #setConfigs(Properties)} instead.
     */
    @Deprecated
    public static EIDASUtil createInstance(final Properties properties) {
        setProperties(immutableMap(properties));
        return INSTANCE;
    }

    /**
     * Returns a new copy of the Properties.
     *
     * @return a new copy of the Properties.
     * @deprecated Use {@link #getProperties()} instead.
     */
    @Nonnull
    @Deprecated
    public Properties getConfigs() {
        return toProperties(getProperties());
    }

    /**
     * Returns the current properties.
     *
     * @return the current properties.
     * @since 1.1
     */
    @Nonnull
    public ImmutableMap<String, String> getProperties() {
        return propertiesRef.get();
    }

    /**
     * Setter for the Properties which loads the default file if the given argument is {@code null}.
     *
     * @param properties The new properties value. If this argument is {@code null}, then the default file is loaded
     * ({@link #EIDAS_UTIL_PROPERTIES}).
     */
    @SuppressWarnings("squid:S3066")
    public static void setConfigs(@Nullable Properties properties) {
        Properties newProperties = properties;
        if (null == newProperties) {
            newProperties = loadConfigs(EIDAS_UTIL_PROPERTIES);
        }
        setProperties(immutableMap(newProperties));
    }

    private static void setProperties(@Nonnull ImmutableMap<String, String> properties) {
        Preconditions.checkNotNull(properties, "properties");
        INSTANCE.propertiesRef.set(properties);
    }

    /**
     * Returns the identifier of some configuration given a set of configurations and the corresponding configuration
     * key.
     *
     * @param configKey The key that IDs some configuration.
     * @return The configuration String value.
     */
    @Nullable
    public static String getConfig(@Nullable String configKey) {
        Preconditions.checkNotNull(configKey, "configKey");
        ImmutableMap<String, String> properties = INSTANCE.getProperties();
        final String propertyValue;
        if (properties.isEmpty()) {
            LOG.warn("BUSINESS EXCEPTION : Configs not loaded - property-Key value is null or empty {} ", configKey);
            propertyValue = configKey;
        } else {
            propertyValue = properties.get(configKey);
            if (StringUtils.isEmpty(propertyValue)) {
                LOG.warn("BUSINESS EXCEPTION : Invalid property-Key value is null or empty {}", configKey);
            }
        }
        return propertyValue;
    }

    /**
     * Gets the Eidas error code in the error message if exists!
     *
     * @param errorMessage The message to get the error code if exists;
     * @return the error code if exists. Returns null otherwise.
     */
    public static String getEidasErrorCode(final String errorMessage) {
        if (StringUtils.isNotBlank(errorMessage)
                && errorMessage.indexOf(EIDASValues.ERROR_MESSAGE_SEP.toString()) >= 0) {
            final String[] msgSplitted = errorMessage.split(EIDASValues.ERROR_MESSAGE_SEP.toString());
            if (msgSplitted.length == 2 && StringUtils.isNumeric(msgSplitted[0])) {
                return msgSplitted[0];
            }
        }
        return null;
    }

    /**
     * Gets the Eidas error message in the saml message if exists!
     *
     * @param errorMessage The message to get in the saml message if exists;
     * @return the error message if exists. Returns the original message otherwise.
     */
    public static String getEidasErrorMessage(final String errorMessage) {
        if (StringUtils.isNotBlank(errorMessage)
                && errorMessage.indexOf(EIDASValues.ERROR_MESSAGE_SEP.toString()) >= 0) {
            final String[] msgSplitted = errorMessage.split(EIDASValues.ERROR_MESSAGE_SEP.toString());
            if (msgSplitted.length == 2 && StringUtils.isNumeric(msgSplitted[0])) {
                return msgSplitted[1];
            }
        }
        return errorMessage;
    }

    public static void loadUtilConfigs() {
        Properties newProperties = loadConfigs(EIDAS_UTIL_PROPERTIES);
        setProperties(immutableMap(newProperties));
    }

    /**
     * Loads the configuration file pointed by the given path.
     *
     * @param path Path to the input file
     * @param logError Whether to log the error or to silently ignore it
     * @return property The loaded Properties
     * @throws InternalErrorEIDASException if the configuration file could not be loaded.
     */
    public static Properties loadConfigs(String path, boolean logError) {
        Properties properties = new Properties();
        InputStream is = null;
        try {
            is = EIDASUtil.class.getClassLoader().getResourceAsStream(path);
            if (is == null) {
                is = indirectedProps(path);
            }
            if (is != null) {
                properties.load(is);
            }
        } catch (IOException e) {
            if (logError) {
                LOG.error("An error occurs when trying to load configuration file: " + path, e);
                throw new InternalErrorEIDASException("5", "Internal server error on loading configurations", e);
            }
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    if (logError) {
                        LOG.error("An error occurred when trying to close resource stream: ", e);
                    }
                    // call ex.addSuppressed(e); when Java 7+ or better use the try with resource
                }
            }
        }
        return properties;
    }

    private static InputStream indirectedProps(String path) throws IOException {
        Properties indirection = EIDASUtil.loadConfigs(CONFIG_LOCATION_PROPERTIES);
        String location = indirection.getProperty(path);
        InputStream is = null;
        if (location != null) {
            if (location.startsWith(CLASSPATH_PREFIX)) {
                is = EIDASUtil.class.getClassLoader()
                        .getResourceAsStream(location.substring(CLASSPATH_PREFIX.length()));
            } else if (location.startsWith(FILE_PREFIX)) {
                is = new FileInputStream(location.substring(FILE_PREFIX.length()));
            }
        }
        return is;
    }

    public static Properties loadConfigs(String path) {
        return loadConfigs(path, true);
    }

    /**
     * @param values a string containing several chunks separated by ;
     * @return a set of chunks extracted from values
     */
    @Nonnull
    public static Set<String> parseSemicolonSeparatedList(@Nullable String values) {
        Set<String> result = new HashSet<String>();
        if (!StringUtils.isEmpty(values)) {
            String[] valuesArr = SEMI_COLON_SEPARATOR_PATTERN.split(values);
            if (valuesArr != null) {
                for (String value : valuesArr) {
                    value = value.trim();
                    if (!StringUtils.isEmpty(value)) {
                        result.add(value);
                    }
                }
            }
        }
        return result;
    }
}
