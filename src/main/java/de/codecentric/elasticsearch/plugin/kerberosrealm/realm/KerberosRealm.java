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
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.JaasKrbUtil;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.admin.cluster.node.liveness.LivenessRequest;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.InternalSystemUser;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.transport.TransportMessage;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Locale;

import static de.codecentric.elasticsearch.plugin.kerberosrealm.support.GSSUtil.GSS_SPNEGO_MECH_OID;

public class KerberosRealm extends Realm<KerberosAuthenticationToken> {

    private static final String ACCEPTOR_KEYTAB_PATH = "acceptor_keytab_path";
    private static final String ACCEPTOR_PRINCIPAL = "acceptor_principal";
    public static final String TYPE = "cc-kerberos";

    private final String acceptorPrincipal;
    private final Path acceptorKeyTabPath;
    private final RolesProvider rolesProvider;

    public KerberosRealm(final RealmConfig config, RolesProvider rolesProvider) {
        super(TYPE, config);
        acceptorPrincipal = config.settings().get(ACCEPTOR_PRINCIPAL, null);
        this.rolesProvider = rolesProvider;
        final String acceptorKeyTab = config.settings().get(ACCEPTOR_KEYTAB_PATH, null);

        if (acceptorPrincipal == null) {
            throw new ElasticsearchException("Unconfigured (but required) property: {}", ACCEPTOR_PRINCIPAL);
        }

        if (acceptorKeyTab == null) {
            throw new ElasticsearchException("Unconfigured (but required) property: {}", ACCEPTOR_KEYTAB_PATH);
        }

        acceptorKeyTabPath = config.env().configFile().resolve(acceptorKeyTab);

        if (!Files.isReadable(acceptorKeyTabPath) || Files.isDirectory(acceptorKeyTabPath)) {
            throw new ElasticsearchException("File not found or not readable: {}", acceptorKeyTabPath.toAbsolutePath());
        }
    }

    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static String getUsernameFromGSSContext(final GSSContext gssContext, final ESLogger logger) {
        if (gssContext.isEstablished()) {
            GSSName gssName = null;
            try {
                gssName = gssContext.getSrcName();
            } catch (final GSSException e) {
                logger.error("Unable to get src name from gss context", e);
            }

            if (gssName != null) {
                return gssName.toString();
            }
        }

        return null;
    }

    @Override
    public boolean supports(final AuthenticationToken token) {
        return token instanceof KerberosAuthenticationToken;
    }

    @Override
    public KerberosAuthenticationToken token(final RestRequest request) {
        if (logger.isDebugEnabled()) {
            logger.debug("Rest request headers: {}", Iterators.toString(request.headers().iterator()));
        }
        final String authorizationHeader = request.header("Authorization");
        final KerberosAuthenticationToken token = token(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Rest request token '{}' for {} successully generated", token, request.path());
        }
        return token;
    }

    private KerberosAuthenticationToken token(final String authorizationHeader) {
        Principal principal;

        if (authorizationHeader != null && acceptorKeyTabPath != null && acceptorPrincipal != null) {

            if (!authorizationHeader.trim().toLowerCase(Locale.ENGLISH).startsWith("negotiate ")) {
                throw new ElasticsearchException("Bad 'Authorization' header");
            } else {

                final byte[] decodedNegotiateHeader = DatatypeConverter.parseBase64Binary(authorizationHeader.substring(10));

                GSSContext gssContext = null;
                byte[] outToken;

                try {
                    final Subject subject = JaasKrbUtil.loginUsingKeytab(acceptorPrincipal, acceptorKeyTabPath, false);

                    final GSSManager manager = GSSManager.getInstance();
                    final int credentialLifetime = GSSCredential.INDEFINITE_LIFETIME;

                    final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                        @Override
                        public GSSCredential run() throws GSSException {
                            return manager.createCredential(null, credentialLifetime, GSS_SPNEGO_MECH_OID, GSSCredential.ACCEPT_ONLY);
                        }
                    };
                    gssContext = manager.createContext(Subject.doAs(subject, action));

                    outToken = Subject.doAs(subject, new AcceptAction(gssContext, decodedNegotiateHeader));

                    if (outToken == null) {
                        logger.warn("Ticket validation not successful, outToken is null");
                        return null;
                    }

                    principal = Subject.doAs(subject, new AuthenticateAction(logger, gssContext));

                } catch (final LoginException e) {
                    logger.error("Login exception due to {}", e, e.toString());
                    throw ExceptionsHelper.convertToRuntime(e);
                } catch (final GSSException e) {
                    logger.error("Ticket validation not successful due to {}", e, e.toString());
                    throw ExceptionsHelper.convertToRuntime(e);
                } catch (final PrivilegedActionException e) {
                    final Throwable cause = e.getCause();
                    if (cause instanceof GSSException) {
                        logger.warn("Service login not successful due to {}", e, e.toString());
                    } else {
                        logger.error("Service login not successful due to {}", e, e.toString());
                    }
                    throw ExceptionsHelper.convertToRuntime(e);
                } finally {
                    if (gssContext != null) {
                        try {
                            gssContext.dispose();
                        } catch (final GSSException e) {
                            // Ignore
                        }
                    }
                    //TODO subject logout
                }

                if (principal == null) {
                    final ElasticsearchException ee = new ElasticsearchException("Principal null");
                    ee.addHeader("kerberos_out_token", DatatypeConverter.printBase64Binary(outToken));
                    throw ee;
                }

                final String username = principal.getName();
                return new KerberosAuthenticationToken(outToken, username);
            }

        } else {
            return null;
        }
    }

    @Override
    public KerberosAuthenticationToken token(final TransportMessage<?> message) {

        if (logger.isDebugEnabled()) {
            logger.debug("Transport request headers: {}", message.getHeaders());
        }

        if (message instanceof LivenessRequest) {
            return KerberosAuthenticationToken.LIVENESS_TOKEN;
        }

        final String authorizationHeader = message.getHeader("Authorization");
        final KerberosAuthenticationToken token = token(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Transport message token '{}' for message {} successully generated", token, message.getClass());
        }
        return token;
    }

    @Override
    public User authenticate(final KerberosAuthenticationToken token) {

        if (token == KerberosAuthenticationToken.LIVENESS_TOKEN) {
            return InternalSystemUser.INSTANCE;
        }

        final String actualUser = token.principal();

        if (actualUser == null || actualUser.isEmpty() || token.credentials() == null) {
            logger.warn("User '{}' cannot be authenticated", actualUser);
            return null;
        }

        String[] userRoles = rolesProvider.getRoles(actualUser);

        logger.debug("User '{}' with roles {} successully authenticated", actualUser, Arrays.toString(userRoles));
        return new User(actualUser, userRoles);
    }

    @Override
    public User lookupUser(final String username) {
        return null;
    }

    @Override
    public boolean userLookupSupported() {
        return false;
    }

    /**
     * This class gets a gss credential via a privileged action.
     */
    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AcceptAction implements PrivilegedExceptionAction<byte[]> {

        GSSContext gssContext;

        byte[] decoded;

        AcceptAction(final GSSContext context, final byte[] decodedToken) {
            this.gssContext = context;
            this.decoded = decodedToken;
        }

        @Override
        public byte[] run() throws GSSException {
            return gssContext.acceptSecContext(decoded, 0, decoded.length);
        }
    }

    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AuthenticateAction implements PrivilegedAction<Principal> {

        private final ESLogger logger;
        private final GSSContext gssContext;

        private AuthenticateAction(final ESLogger logger, final GSSContext gssContext) {
            super();
            this.logger = logger;
            this.gssContext = gssContext;
        }

        @Override
        public Principal run() {
            return new SimpleUserPrincipal(getUsernameFromGSSContext(gssContext, logger));
        }
    }

    private static class SimpleUserPrincipal implements Principal, Serializable {

        private static final long serialVersionUID = -1;
        private final String username;

        SimpleUserPrincipal(final String username) {
            super();
            this.username = username;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((username == null) ? 0 : username.hashCode());
            return result;
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final SimpleUserPrincipal other = (SimpleUserPrincipal) obj;
            if (username == null) {
                if (other.username != null) {
                    return false;
                }
            } else if (!username.equals(other.username)) {
                return false;
            }
            return true;
        }

        @Override
        public String getName() {
            return this.username;
        }

        @Override
        public String toString() {
            return "[principal: " + this.username + "]";
        }
    }
}
