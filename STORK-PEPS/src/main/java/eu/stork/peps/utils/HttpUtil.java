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

package eu.stork.peps.utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;

/**
 * contains http utilities
 */
public class HttpUtil {
    private HttpUtil(){
    }
    //rebuilds a get url with the parameters in the current request
    public static String rebuildGetUrl(String baseUrl, HttpServletRequest request, HttpServletResponse response){
        StringBuilder newUrl=new StringBuilder(baseUrl);
        boolean firstValue=true;
        newUrl.append("?");
        Enumeration paramNames=request.getParameterNames();
        while(paramNames.hasMoreElements()){
            String paramName=(String)paramNames.nextElement();
            String paramValues[]=request.getParameterValues(paramName);
            for(int i=0;paramValues!=null && i<paramValues.length;i++){
                if(firstValue) {
                    firstValue=false;
                }else{
//NOSONAR                    newUrl.append('&');
                }
//NOSONAR                newUrl.append(paramName);
//NOSONAR                newUrl.append("=");
//NOSONAR                newUrl.append(paramValues[i]);
            }
        }

        return response.encodeURL(newUrl.toString());
    }

}
