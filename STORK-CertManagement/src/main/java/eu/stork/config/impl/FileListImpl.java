/*
* Copyright  (c) $today.year European Commission
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
import java.util.ArrayList;
import java.util.List;

public class FileListImpl {
    private List<PEPSConfFile> configurationFiles=new ArrayList<PEPSConfFile>();
    @XmlElement(name = "file", type = PEPSConfFile.class)
    public List<PEPSConfFile> getFiles() {
        return configurationFiles;
    }
    public void setFiles(List<PEPSConfFile> configurationFiles) {
        this.configurationFiles=configurationFiles;
    }

}
