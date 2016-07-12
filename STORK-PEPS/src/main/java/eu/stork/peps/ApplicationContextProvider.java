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
package eu.stork.peps;

import eu.stork.peps.auth.commons.PEPSParameters;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.cpeps.AUCPEPSUtil;
import eu.stork.peps.auth.engine.core.SAMLEngineModuleI;
import eu.stork.peps.auth.metadata.PEPSMetadataProcessor;
import eu.stork.peps.auth.speps.AUSPEPSSAML;
import eu.stork.peps.security.ConfigurationSecurityBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


public class ApplicationContextProvider implements ApplicationContextAware {
    private static ApplicationContext applicationContext = null;

    public static ApplicationContext getApplicationContext() {
        return applicationContext;
    }

    public void setApplicationContext(ApplicationContext ctx){
        ApplicationContextProvider.setGlobalAppContext(ctx);

    }
    private static void setGlobalAppContext(ApplicationContext ctx){
        applicationContext = ctx;
        booleanMap=new HashMap<String, Boolean>();
        //check production flag
        AUCPEPSUtil util= ApplicationContextProvider.getApplicationContext().getBean(AUCPEPSUtil.class);
        if( Boolean.parseBoolean(util.getConfigs().getProperty(PEPSValues.EIDAS_PRODUCTION.toString()))){
            resetParamsForProduction(util.getConfigs());
        }

    }

    private static void resetParamsForProduction(Properties props){
        //do not allow self signed certificates
        props.setProperty(SAMLEngineModuleI.SELF_SIGNED_PROPERTY, "true");
        //do check certificates validiy period
        props.setProperty(SAMLEngineModuleI.CHECK_VALIDITY_PERIOD_PROPERTY, "true");
        //activate metadata
        props.setProperty(PEPSValues.PEPS_METADATA_ACTIVE.toString(), "true");

        props.setProperty(PEPSValues.PEPS_METADATA_CHECK_SIGNATURE.toString(), "true");
        //enforce https for remote metadata
        PEPSMetadataProcessor pepsMetadataProcessor=applicationContext.getBean(PEPSMetadataProcessor.class);
        pepsMetadataProcessor.setRestrictHttp(true);

        //validate binding
        props.setProperty(PEPSParameters.VALIDATE_BINDING.toString(), "true");

        //enable content security settings
        ConfigurationSecurityBean securityBean = applicationContext.getBean(ConfigurationSecurityBean.class);
        securityBean.setIncludeHSTS(true);
        securityBean.setIncludeMozillaDirectives(true);
        securityBean.setIncludeXContentTypeOptions(true);
        securityBean.setIncludeXFrameOptions(true);
        securityBean.setIsContentSecurityPolicyActive(true);

        //enforce citizen country the same as CPEPS country
        AUSPEPSSAML auspepssaml=applicationContext.getBean(AUSPEPSSAML.class);
        auspepssaml.setCheckCitizenCertificateCPepsCertificate(true);

        //enforce reponse encryption
        props.setProperty(PEPSValues.RESPONSE_ENCRYPTION_MANDATORY.toString(), "true");
    }
    private static Map<String, Boolean> booleanMap=new HashMap<String, Boolean>();
    public static Boolean getPepsParameterBool(String parameterName){
        if(!booleanMap.containsKey(parameterName)){
            synchronized (applicationContext){
                AUCPEPSUtil util= ApplicationContextProvider.getApplicationContext().getBean(AUCPEPSUtil.class);
                if(util.getConfigs()!=null) {
                    booleanMap.put(parameterName, Boolean.parseBoolean(util.getConfigs().getProperty(parameterName)));
                }
            }
        }
        return booleanMap.get(parameterName);
    }
}
