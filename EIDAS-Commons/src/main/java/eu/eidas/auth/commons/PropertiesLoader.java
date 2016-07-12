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

import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;

/**
 * Class used to dynamically load resources
 *
 * @author vanegdi
 * @since 1.2.2
 */
public final class PropertiesLoader {
    private static final boolean THROW_ON_LOAD_FAILURE = true;
    private static final boolean LOAD_AS_RESOURCE_BUNDLE = false;
    private static final String SUFFIX = ".properties";
    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(PropertiesLoader.class.getName());

    private PropertiesLoader(){

    }
    /**
     * Looks up a resource named 'name' in the classpath. The resource must map
     * to a file with .properties extention. The name is assumed to be absolute
     * and can use either "/" or "." for package segment separation with an
     * optional leading "/" and optional ".properties" suffix. Thus, the
     * following names refer to the same resource:
     *
     * <pre>
     * some.pkg.Resource
     * some.pkg.Resource.properties
     * some/pkg/Resource
     * some/pkg/Resource.properties
     * /some/pkg/Resource
     * /some/pkg/Resource.properties
     * </pre>
     *
     * @param name
     *            classpath resource name [may not be null]
     * @param loader
     *            classloader through which to load the resource [null is
     *            equivalent to the application loader]
     *
     * @return resource converted to java.util.Properties [may be null if the
     *         resource was not found and THROW_ON_LOAD_FAILURE is false]
     * @throws IllegalArgumentException
     *             if the resource was not found and THROW_ON_LOAD_FAILURE is
     *             true
     */
    public static Properties loadProperties(String name, ClassLoader loader) {
        if (name == null) {
            throw new IllegalArgumentException("null input: name");
        }
        ClassLoader propLoader = loader;
        String propName=name;
        if (propName.startsWith("/")) {
            propName = propName.substring(1);
        }
        if (propLoader == null) {
            propLoader = ClassLoader.getSystemClassLoader();
        }

        if (propName.endsWith(SUFFIX)) {
            propName = propName.substring(0, propName.length() - SUFFIX.length());
        }
        Properties result=helperLoaderProperties(propLoader, propName);

        if (THROW_ON_LOAD_FAILURE && (result == null)) {
            throw new IllegalArgumentException("could not load [" + propName + "]" +
                    " as " +
                    (LOAD_AS_RESOURCE_BUNDLE ? "a resource bundle"
                            : "a classloader resource"));
        }

        return result;
    }

    private static Properties populateFromResources(final ResourceBundle rb){
        Properties result = new Properties();

        for (Enumeration<String> keys = rb.getKeys();
             keys.hasMoreElements();) {
            final String key = keys.nextElement();
            final String value = rb.getString(key);

            result.put(key, value);
        }
        return result;
    }
    private static Properties helperLoaderProperties(ClassLoader propLoader, String propertyName){
        Properties result = null;
        String propName=propertyName;
        InputStream in = null;

        try {

            propName = propName.replace('.', '/');
            if (LOAD_AS_RESOURCE_BUNDLE) {

                // Throws MissingResourceException on lookup failures:
                final ResourceBundle rb = ResourceBundle.getBundle(propName,Locale.getDefault(), propLoader);
                result=populateFromResources(rb);

            } else {

                if (!propName.endsWith(SUFFIX)) {
                    propName = propName.concat(SUFFIX);
                }

                // Returns null on lookup failures:
                in = propLoader.getResourceAsStream(propName);

                if (in != null) {
                    result = new Properties();
                    // Can throw IOException
                    result.load(in);
                }
            }
        } catch (Exception e) {
            LOG.info("Generic exception occurs {}", e.getMessage());
            LOG.debug("Generic exception occurs {}", e);
            result = null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    LOG.debug("IOException occurs in close {}", e);
                }
            }
        }
        return result;
    }
    /**
     * A convenience overload of {@link #loadProperties(String, ClassLoader)}
     * that uses the current thread's context classloader.
     */
    public static Properties loadProperties(final String name) {
        return loadProperties(name,
                Thread.currentThread().getContextClassLoader());
    }

    /**
     * Loads the properties defined in an xml file with the format
     * <//?xml version="1.0" encoding="UTF-8" standalone="no"?>
     * <//!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
     *   <properties>
     *       <comment>Comment</comment>
     *       <entry key="keyName">Some Value</entry>
     *   </properties>
     * @param xmlFilePath
     * @return Object @Properties
     */
    public static Properties loadPropertiesXMLFile(String xmlFilePath){
        Properties props;
        InputStream fileProperties = null;
        try{
            if(StringUtils.isEmpty(xmlFilePath) || !StringUtils.endsWith(xmlFilePath,"xml")){
                throw new InternalErrorEIDASException(EIDASErrors.INTERNAL_ERROR.errorCode(), EIDASErrors.INTERNAL_ERROR.errorMessage(),"Not valid file!");
            }else {
                props = new Properties();
                fileProperties = new FileInputStream(xmlFilePath);
                //load the xml file into properties format
                props.loadFromXML(fileProperties);
                fileProperties.close();
            }
            return props;
        }catch(Exception e){
            LOG.error("ERROR : " + e.getMessage());
            throw new InternalErrorEIDASException(EIDASErrors.INTERNAL_ERROR.errorCode(), EIDASErrors.INTERNAL_ERROR.errorMessage(), e);
        }finally {
            try{
                if(fileProperties!=null) {
                    fileProperties.close();
                }
            }catch(IOException ioe){
                LOG.error("error closing the file:",ioe);
            }
        }
    }
}
