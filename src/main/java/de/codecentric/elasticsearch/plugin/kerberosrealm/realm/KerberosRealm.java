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

import com.google.common.collect.Iterators;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosToken.KerberosTokenFactory;
import org.elasticsearch.action.admin.cluster.node.liveness.LivenessRequest;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.InternalSystemUser;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.transport.TransportMessage;

import java.util.Arrays;

public class KerberosRealm extends Realm<KerberosToken> {

    public static final String TYPE = "kerberos";
    private static final String HTTP_AUTHORIZATION = "Authorization";
    private final RolesProvider rolesProvider;
    private final KerberosAuthenticator kerberosAuthenticator;

    public KerberosRealm(RealmConfig config, KerberosAuthenticator kerberosAuthenticator, RolesProvider rolesProvider) {
        super(TYPE, config);
        this.rolesProvider = rolesProvider;
        this.kerberosAuthenticator = kerberosAuthenticator;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof KerberosToken;
    }

    @Override
    public KerberosToken token(RestRequest request) {
        if (logger.isDebugEnabled()) {
            logger.debug("Rest request headers: {}", Iterators.toString(request.headers().iterator()));
        }
        String authorizationHeader = request.header(HTTP_AUTHORIZATION);
        KerberosToken token = new KerberosTokenFactory().extractToken(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Rest request token '{}' for {} successully generated", token, request.path());
        }
        return token;
    }

    @Override
    public KerberosToken token(TransportMessage<?> message) {
        if (logger.isDebugEnabled()) {
            logger.debug("Transport request headers: {}", Iterators.toString(message.getHeaders().iterator()));
        }

        if (message instanceof LivenessRequest) {
            return LivenessToken.INSTANCE;
        }

        String authorizationHeader = message.getHeader(HTTP_AUTHORIZATION);
        KerberosToken token = new KerberosTokenFactory().extractToken(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Transport message token '{}' for message {} successully generated", token, message.getClass());
        }
        return token;
    }

    @Override
    public User authenticate(KerberosToken token) {
        if (token instanceof LivenessToken) {
            return InternalSystemUser.INSTANCE;
        }

        String actualUser = kerberosAuthenticator.authenticate(token);

        if (actualUser == null) {
            logger.warn("User cannot be authenticated");
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
