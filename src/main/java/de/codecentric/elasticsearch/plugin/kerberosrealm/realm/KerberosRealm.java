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
           and Apache Tomcat project https://tomcat.apache.org/ (see comments and NOTICE)
 */
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.InternalSystemUser;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.transport.TransportMessage;

import java.util.Arrays;

public class KerberosRealm extends Realm<KerberosToken> {

    public static final String TYPE = "cc-kerberos";

    private final RolesProvider rolesProvider;
    private final KerberosTokenExtractor tokenExtractor;

    public KerberosRealm(RealmConfig config, KerberosTokenExtractor tokenExtractor, RolesProvider rolesProvider) {
        super(TYPE, config);
        this.rolesProvider = rolesProvider;
        this.tokenExtractor = tokenExtractor;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof KerberosToken;
    }

    @Override
    public KerberosToken token(RestRequest request) {
        return tokenExtractor.extractToken(request);
    }

    @Override
    public KerberosToken token(TransportMessage<?> message) {
        return tokenExtractor.extractToken(message);
    }

    @Override
    public User authenticate(KerberosToken token) {
        if (token == KerberosToken.LIVENESS_TOKEN) {
            return InternalSystemUser.INSTANCE;
        }

        final String actualUser = token.principal();

        if (actualUser.isEmpty() || token.credentials() == null) {
            logger.warn("User '{}' cannot be authenticated", actualUser);
            return null;
        }

        String[] userRoles = rolesProvider.getRoles(actualUser);

        logger.debug("User '{}' with roles {} successully authenticated", actualUser, Arrays.toString(userRoles));
        return new User(actualUser, userRoles);
    }

    @Override
    public User lookupUser(String username) {
        return null;
    }

    @Override
    public boolean userLookupSupported() {
        return false;
    }
}
