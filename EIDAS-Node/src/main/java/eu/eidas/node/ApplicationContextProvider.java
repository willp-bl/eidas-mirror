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
package eu.eidas.node;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.commons.EidasParameterKeys;
import eu.eidas.auth.engine.core.impl.CertificateValidator;
import eu.eidas.node.auth.connector.AUCONNECTORSAML;
import eu.eidas.node.auth.service.AUSERVICEUtil;
import eu.eidas.node.security.ConfigurationSecurityBean;


public class ApplicationContextProvider implements ApplicationContextAware {
    private static ApplicationContext applicationContext = null;

    public static ApplicationContext getApplicationContext() {
        return applicationContext;
    }

    public void setApplicationContext(ApplicationContext ctx) {
        ApplicationContextProvider.setGlobalAppContext(ctx);

    }
    private static void setGlobalAppContext(ApplicationContext ctx){
        applicationContext = ctx;
        booleanMap=new HashMap<String, Boolean>();
        //check production flag
        AUSERVICEUtil util= ApplicationContextProvider.getApplicationContext().getBean(AUSERVICEUtil.class);
        if( Boolean.parseBoolean(util.getConfigs().getProperty(EIDASValues.EIDAS_PRODUCTION.toString()))){
            resetParamsForProduction(util.getConfigs());
        }

    }

    private static void resetParamsForProduction(Properties props){
        //do not allow self signed certificates
        props.setProperty(CertificateValidator.DISALLOW_SELF_SIGNED_CERTIFICATE_PROPERTY, "true");
        //do check certificates validiy period
        props.setProperty(CertificateValidator.CHECK_VALIDITY_PERIOD_PROPERTY, "true");
        //activate metadata
        props.setProperty(EIDASValues.METADATA_ACTIVE.toString(), "true");

        //validate binding
        props.setProperty(EidasParameterKeys.VALIDATE_BINDING.toString(), "true");

        //enable content security settings
        ConfigurationSecurityBean securityBean = applicationContext.getBean(ConfigurationSecurityBean.class);
        securityBean.setIncludeHSTS(true);
        securityBean.setIncludeMozillaDirectives(true);
        securityBean.setIncludeXContentTypeOptions(true);
        securityBean.setIncludeXFrameOptions(true);
        securityBean.setIsContentSecurityPolicyActive(true);

        //enforce citizen country the same as ServiceProxy country
        AUCONNECTORSAML auConnectorSaml=applicationContext.getBean(AUCONNECTORSAML.class);
        auConnectorSaml.setCheckCitizenCertificateServiceCertificate(true);

        //enforce reponse encryption
        props.setProperty(EIDASValues.RESPONSE_ENCRYPTION_MANDATORY.toString(), "true");
    }
    private static Map<String, Boolean> booleanMap=new HashMap<String, Boolean>();
    public static Boolean getNodeParameterBool(String parameterName){
        if(!booleanMap.containsKey(parameterName)){
            synchronized (applicationContext){
                AUSERVICEUtil util= ApplicationContextProvider.getApplicationContext().getBean(AUSERVICEUtil.class);
                if(util.getConfigs()!=null) {
                    booleanMap.put(parameterName, Boolean.parseBoolean(util.getConfigs().getProperty(parameterName)));
                }
            }
        }
        return booleanMap.get(parameterName);
    }
}
