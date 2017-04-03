/*
   Copyright 2015 codecentric AG

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Author: Hendrik Saly <hendrik.saly@codecentric.de>
 */
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.shield.authc.AuthenticationToken;

import javax.xml.bind.DatatypeConverter;
import java.util.Locale;
import java.util.Objects;

public class KerberosToken implements AuthenticationToken {
    private byte[] token;

    public KerberosToken(byte[] token) {
        this.token = Objects.requireNonNull(token);
    }

    @Override
    public void clearCredentials() {
        this.token = null;
    }

    @Override
    public byte[] credentials() {
        return token;
    }

    @Override
    public String principal() {
        return null;
    }

    public static class KerberosTokenFactory {
        public KerberosToken extractToken(String authorizationHeader) {
            if (authorizationHeader == null) {
                return null;
            } else if (!authorizationHeader.trim().toLowerCase(Locale.ENGLISH).startsWith("negotiate ")) {
                throw new ElasticsearchException("Bad 'Authorization' header");
            } else {
                byte[] token = DatatypeConverter.parseBase64Binary(authorizationHeader.substring(10));
                return new KerberosToken(token);
            }
        }
    }
}
