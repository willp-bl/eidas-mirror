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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * @author vanegdi on 15/08/2015.
 * Remark : moved from private to package class for security reasons
 */
class OrderedAttributeIterator implements Iterator<PersonalAttribute> {
    /**
     * Logger object.
     */
    private static final Logger LOG = LoggerFactory.getLogger(OrderedAttributeIterator.class.getName());
    private PersonalAttributeList pal;
    private Iterator<String> keyIterator;

    public OrderedAttributeIterator(PersonalAttributeList palArg) {
        this.pal = palArg;
        keyIterator = palArg.getInsertOrder().iterator();
    }

    @Override
    public boolean hasNext() {
        return keyIterator.hasNext();
    }

    @Override
    public PersonalAttribute next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        return pal.get(keyIterator.next());
    }

    @Override
    public void remove() {
        LOG.error("Not implemented");
    }
}
