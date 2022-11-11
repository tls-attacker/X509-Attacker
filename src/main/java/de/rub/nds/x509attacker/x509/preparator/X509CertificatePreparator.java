/*
 * Copyright 2022 robertmerget.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.x509attacker.x509.base.X509Certificate;

public class X509CertificatePreparator extends Asn1FieldPreparator<X509Certificate> {

    public X509CertificatePreparator(X509Certificate field) {
        super(field);
    }

    @Override
    protected byte[] encodeContent() {
    }

}
