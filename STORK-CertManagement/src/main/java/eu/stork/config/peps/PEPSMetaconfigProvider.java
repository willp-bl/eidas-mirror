/*
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 *
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */
package eu.stork.config.peps;

import eu.stork.config.impl.PEPSConfFile;

import java.util.*;

/**
 * stores metadata information and performs operation on it
 */
public abstract class PEPSMetaconfigProvider {
    private Map<String, PEPSParameterMeta> parameterMap=new HashMap<String, PEPSParameterMeta>();
    private List<String> parameterOrder=new ArrayList<String>();
    private Map<String, List<PEPSParameterMeta>> categorizedParameters=new HashMap<String, List<PEPSParameterMeta>>();
    private List<PEPSParameterCategory> categories=new ArrayList<PEPSParameterCategory>();
    public void addMetadata(String paramName, PEPSParameterMeta parameter){
        parameterMap.put(paramName, parameter);
        parameterOrder.add(paramName);
    }
    public List<PEPSParameterCategory> getCategories(){
        return categories;
    }
    public PEPSParameterMeta getMetadata(String parameterName){
        return parameterMap.get(parameterName);
    }
    public List<PEPSParameterMeta> getCategoryParameter(String categoryName){
        return getCategorizedParameters().get(categoryName);
    }

    public Map<String, List<PEPSParameterMeta>> getCategorizedParameters() {
        if(categorizedParameters.isEmpty()){
            synchronized (PEPSMetaconfigProvider.class){
                if(categorizedParameters.isEmpty()) {
                    for(PEPSParameterCategory c:categories){
                        categorizedParameters.put(c.getName(), new ArrayList<PEPSParameterMeta>());
                    }

                    for(String paramName:parameterOrder){
                        PEPSParameterMeta p = parameterMap.get(paramName);
                        if(p!=null){
                            for(String categoryName:p.getCategories()){
                                if(categorizedParameters.containsKey(categoryName)){
                                    categorizedParameters.get(categoryName).add(p);
                                }
                            }

                        }
                    }
                }
            }
        }
        return categorizedParameters;
    }

    public void setCategorizedParameters(Map<String, List<PEPSParameterMeta>> categorizedParameter) {
        this.categorizedParameters = categorizedParameter;
    }
    public abstract PEPSConfFile getDefaultConfFile();
}
