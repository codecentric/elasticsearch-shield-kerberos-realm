package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import com.google.common.collect.Iterators;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.JaasKrbUtil;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.admin.cluster.node.liveness.LivenessRequest;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.transport.TransportMessage;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Locale;

import static de.codecentric.elasticsearch.plugin.kerberosrealm.support.GSSUtil.GSS_SPNEGO_MECH_OID;

public class KerberosTokenExtractor {

    private static final String ACCEPTOR_KEYTAB_PATH = "acceptor_keytab_path";
    private static final String ACCEPTOR_PRINCIPAL = "acceptor_principal";

    private final String acceptorPrincipal;
    private final Path acceptorKeyTabPath;
    private final ESLogger logger;

    public KerberosTokenExtractor(RealmConfig config) {
        logger = config.logger(RolesProvider.class);
        acceptorPrincipal = config.settings().get(ACCEPTOR_PRINCIPAL, null);
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

    public KerberosToken extractToken(RestRequest request) {
        if (logger.isDebugEnabled()) {
            logger.debug("Rest request headers: {}", Iterators.toString(request.headers().iterator()));
        }
        final String authorizationHeader = request.header("Authorization");
        final KerberosToken token = extractToken(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Rest request token '{}' for {} successully generated", token, request.path());
        }
        return token;
    }

    public KerberosToken extractToken(final TransportMessage<?> message) {

        if (logger.isDebugEnabled()) {
            logger.debug("Transport request headers: {}", message.getHeaders());
        }

        if (message instanceof LivenessRequest) {
            return KerberosToken.LIVENESS_TOKEN;
        }

        final String authorizationHeader = message.getHeader("Authorization");
        final KerberosToken token = extractToken(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Transport message token '{}' for message {} successully generated", token, message.getClass());
        }
        return token;
    }

    private KerberosToken extractToken(String authorizationHeader) {
        String username;

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

                    final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                        @Override
                        public GSSCredential run() throws GSSException {
                            return manager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, GSS_SPNEGO_MECH_OID, GSSCredential.ACCEPT_ONLY);
                        }
                    };
                    gssContext = manager.createContext(Subject.doAs(subject, action));

                    outToken = Subject.doAs(subject, new AcceptAction(gssContext, decodedNegotiateHeader));

                    if (outToken == null) {
                        logger.warn("Ticket validation not successful, outToken is null");
                        return null;
                    }

                    username = Subject.doAs(subject, new AuthenticateAction(logger, gssContext));

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

                if (username == null) {
                    final ElasticsearchException ee = new ElasticsearchException("Username null");
                    ee.addHeader("kerberos_out_token", DatatypeConverter.printBase64Binary(outToken));
                    throw ee;
                }

                return new KerberosToken(outToken, username);
            }
        } else {
            return null;
        }
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
    private static class AuthenticateAction implements PrivilegedAction<String> {

        private final ESLogger logger;
        private final GSSContext gssContext;

        private AuthenticateAction(final ESLogger logger, final GSSContext gssContext) {
            super();
            this.logger = logger;
            this.gssContext = gssContext;
        }

        @Override
        public String run() {
            return getUsernameFromGSSContext(gssContext, logger);
        }
    }
}
