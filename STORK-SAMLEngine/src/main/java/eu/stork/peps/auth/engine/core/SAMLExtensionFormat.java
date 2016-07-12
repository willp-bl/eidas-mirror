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
package eu.stork.peps.auth.engine.core;

import java.util.*;

/**
 * defines which extensions to be processed in a saml message
 */
public class SAMLExtensionFormat {
    private List<SAMLExtension> samlExtensions;
    private String baseURI;
    private String name;
    public static final String EIDAS_FORMAT_NAME="eidas";
    public static final String STORK1_FORMAT_NAME="stork1";

    public static final SAMLExtensionFormat STORK10=new SAMLExtensionFormat(STORK1_FORMAT_NAME, SAMLCore.STORK10_NS.getValue(), SAMLCore.STORK10_PREFIX.getValue(),SAMLCore.STORK10P_NS.getValue(), SAMLCore.STORK10P_PREFIX.getValue(), SAMLCore.STORK10_BASE_URI.getValue());
    public static final SAMLExtensionFormat EIDAS10=new SAMLExtensionFormat(EIDAS_FORMAT_NAME, SAMLCore.STORK10_NS.getValue(), SAMLCore.STORK10_PREFIX.getValue(),SAMLCore.STORK10P_NS.getValue(), SAMLCore.STORK10P_PREFIX.getValue(), SAMLCore.EIDAS10_BASE_URI.getValue());
    public static final Map<String, SAMLExtensionFormat> AVAILABLE_FORMATS=Collections.unmodifiableMap (new HashMap<String, SAMLExtensionFormat>(){
        {
            put(EIDAS_FORMAT_NAME, EIDAS10);
            put(STORK1_FORMAT_NAME, STORK10);
        }
    } );


    private SAMLExtensionFormat(){
        samlExtensions =new ArrayList<SAMLExtension>();
    }
    public SAMLExtensionFormat(String formatName, String assertionNS, String assertionPrefix, String protocolNS, String protocolPrefix, String baseURI){
        this();
        name=formatName;
        samlExtensions.add(new SAMLExtension(assertionNS, assertionPrefix));
        samlExtensions.add(new SAMLExtension(protocolNS, protocolPrefix));
        setBaseURI(baseURI);
    }
    public SAMLExtensionFormat(SAMLExtension[] SAMLExtensions){
        this();
        samlExtensions = Arrays.asList(SAMLExtensions);
    }

    public String getAssertionNS() {
        if(samlExtensions!=null && !samlExtensions.isEmpty()){
            return samlExtensions.get(0).getNamespace();
        }
        return null;
    }
    public String getAssertionPrefix(){
        if(samlExtensions!=null && !samlExtensions.isEmpty()){
            return samlExtensions.get(0).getPrefix();
        }
        return null;
    }
    public String getBaseURI() {
        return baseURI;
    }

    public void setBaseURI(String baseURI) {
        this.baseURI = baseURI;
    }

    public String getName() {
        return name;
    }
}
