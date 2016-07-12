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
package eu.stork.config.impl;

import javax.xml.bind.annotation.XmlElement;
import java.util.List;

/**
 */
public class PEPSMetaconfigListImpl {
    List<CategoryImpl> categories;
    List<PEPSParameterMetaImpl> pepsParameterMetaList;
    @XmlElement(name = "parameter", type = PEPSParameterMetaImpl.class)
    public List<PEPSParameterMetaImpl> getPEPSParameterMetadaList() {
        return pepsParameterMetaList;
    }

    public void setPEPSParameterMetadaList(List<PEPSParameterMetaImpl> pepsParameterMetaList) {
        this.pepsParameterMetaList = pepsParameterMetaList;
    }
}
