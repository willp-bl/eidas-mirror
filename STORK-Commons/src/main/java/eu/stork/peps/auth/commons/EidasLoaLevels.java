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

package eu.stork.peps.auth.commons;

import java.util.HashMap;
import java.util.Map;

/**
 * @author vanegdi on 7/08/2015.
 */
public enum EidasLoaLevels {

    LOW("http://eidas.europa.eu/LoA/low", 1),
    SUBSTANTIAL("http://eidas.europa.eu/LoA/substantial",2),
    HIGH("http://eidas.europa.eu/LoA/high",3);
    private String value;
    private int order;
    private static Map<String, EidasLoaLevels> eidasLoaLevelsHashMap =new HashMap<String, EidasLoaLevels>();
    static{
        for(EidasLoaLevels e:values()){
            eidasLoaLevelsHashMap.put(e.stringValue(), e);
        }
    }
    EidasLoaLevels(String valueArg, int orderArg){
        this.value=valueArg;
        this.order=orderArg;
    }
    public String stringValue(){
        return value;
    }
    public int numericValue(){
        return order;
    }
    public static EidasLoaLevels getLevel(String value){
        return eidasLoaLevelsHashMap.get(value);
    }
}
