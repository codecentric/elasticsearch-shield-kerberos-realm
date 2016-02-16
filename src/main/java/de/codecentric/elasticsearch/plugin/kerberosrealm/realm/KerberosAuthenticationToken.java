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

import java.util.Objects;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.shield.authc.AuthenticationToken;

public class KerberosAuthenticationToken implements AuthenticationToken {

    static final KerberosAuthenticationToken LIVENESS_TOKEN = new KerberosAuthenticationToken(new byte[]{1,2,3}, "LIVENESS_TOKEN");
    protected final ESLogger logger = Loggers.getLogger(this.getClass());
    private byte[] outToken;
    private final String principal;

    public KerberosAuthenticationToken(final byte[] outToken, final String principal) {
        super();
        this.outToken = Objects.requireNonNull(outToken);
        this.principal = Objects.requireNonNull(principal);
    }

    @Override
    public void clearCredentials() {
        this.outToken = null;
        logger.debug("credentials cleared for {}", toString());
    }

    @Override
    public Object credentials() {
        return outToken;
    }

    @Override
    public String principal() {
        return principal;
    }

    @Override
    public String toString() {
        return "KerberosAuthenticationToken [principal=" + principal + ", credentials null?: " + (outToken == null) + "]";
    }

}
