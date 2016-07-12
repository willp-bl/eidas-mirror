/*
 * Copyright (c) 2015 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.eidas.node.utils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import eu.eidas.auth.commons.CountrySpecificService;
import eu.eidas.node.ApplicationContextProvider;
import eu.eidas.node.auth.service.InactiveIntegrationPlugin;

public class CountrySpecificUtil implements ApplicationContextAware {

    /**
     * set of COUNTRIES for which handlers are registering
     */
    private final Map<String, CountrySpecificService> registeredCountries = Collections.synchronizedMap(new HashMap<String, CountrySpecificService>());
    private static final String PLUGIN_ACTIVATION_PREFIX="active.module.plugin";
    private boolean pluginsLoaded=false;
    static CountrySpecificUtil activeInstance=null;

    private CountrySpecificUtil(){
        // Private constructor to prevent instantiation
    }

    public CountrySpecificService getCountryHandler(String isoCode){
        if(isoCode==null || isoCode.isEmpty()) {
            return null;
        }
        String normalizedISOCode=isoCode.toUpperCase(Locale.ENGLISH);
        if(registeredCountries.isEmpty()) {
            loadCountryHandlers();
        }
        CountrySpecificService cachedService= registeredCountries.get(normalizedISOCode);
        return cachedService;
    }

    /**
     * prepares a cache of country handlers found in the classpath
     */
    public void loadCountryHandlers(){
        synchronized(CountrySpecificUtil.class) {
            if(!pluginsLoaded) {
                ApplicationContext ctx = ApplicationContextProvider.getApplicationContext();
                Map<String, Boolean> configuredPlugins=getConfiguredPlugins(ctx);
                for (String iso : configuredPlugins.keySet()) {
                    registeredCountries.put(iso, new InactiveIntegrationPlugin(iso));
                }
                Map specificCountriesMap = ctx.getBeansOfType(CountrySpecificService.class);
                for (Object o : specificCountriesMap.values()) {
                    CountrySpecificService handler = (CountrySpecificService) o;
                    //plugins present as jar files but not activated through configuration will be ignored
                    if(registeredCountries.containsKey(handler.getIsoCode())
                            && configuredPlugins.containsKey(handler.getIsoCode())
                            && configuredPlugins.get(handler.getIsoCode())) {
                        registeredCountries.put(handler.getIsoCode(), handler);
                    }
                }
                pluginsLoaded = true;
            }
        }

    }

    private Map<String, Boolean> getConfiguredPlugins(ApplicationContext ctx){
        Properties eidasConfig=(Properties)ctx.getBean("nodeProps");
        Map<String, Boolean> confPlugins=new HashMap<String, Boolean>();
        if(eidasConfig!=null){
            for(String key:eidasConfig.stringPropertyNames()){
                if(key.startsWith(PLUGIN_ACTIVATION_PREFIX)){
                    if(Boolean.valueOf(eidasConfig.getProperty(key))) {
                        confPlugins.put(key.substring(PLUGIN_ACTIVATION_PREFIX.length()), Boolean.TRUE);
                    }else {
                        confPlugins.put(key.substring(PLUGIN_ACTIVATION_PREFIX.length()), Boolean.FALSE);
                    }
                }
            }
        }
        return confPlugins;
    }

    /**
     *
     * @param req the request
     * @return true when there is a handler for the given country and it was registered
     * (getCountryHandler was called)
     */
    public static boolean isRequestAllowed(HttpServletRequest req){
        if(!activeInstance.pluginsLoaded) {
            activeInstance.loadCountryHandlers();
        }
        for (Object o : activeInstance.registeredCountries.values()) {
            CountrySpecificService handler = (CountrySpecificService) o;
            if(handler.isActive() && handler.allowRequestThroughFilter(req)){
                return true;
            }
        }
        return false;
    }
    private static void activeInstanceSetter(CountrySpecificUtil instance){
        activeInstance=instance;
    }
    public void setApplicationContext(ApplicationContext ctx) throws BeansException {
        CountrySpecificUtil.activeInstanceSetter(ApplicationContextProvider.getApplicationContext().getBean(CountrySpecificUtil.class));
    }

}
