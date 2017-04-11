package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.support.LoginUsingKeytab;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.shield.authc.RealmConfig;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import static de.codecentric.elasticsearch.plugin.kerberosrealm.realm.support.GSSUtil.GSS_SPNEGO_MECH_OID;

public class KerberosAuthenticator {

    private static final String ACCEPTOR_KEYTAB_PATH = "acceptor_keytab_path";
    private static final String ACCEPTOR_PRINCIPAL = "acceptor_principal";

    private final String acceptorPrincipal;
    private final Path acceptorKeyTabPath;
    private final ESLogger logger;

    public KerberosAuthenticator(RealmConfig config) {
        logger = config.logger(RolesProvider.class);
        acceptorPrincipal = config.settings().get(ACCEPTOR_PRINCIPAL, null);
        final String acceptorKeyTab = config.settings().get(ACCEPTOR_KEYTAB_PATH, null);

        if (acceptorPrincipal == null || acceptorPrincipal.isEmpty()) {
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

    private Subject loginUsingKeytab() {
        try {
            return new LoginUsingKeytab(acceptorPrincipal, acceptorKeyTabPath).login();
        } catch (LoginException e) {
            logger.error("Login exception due to {}", e, e.toString());
            throw ExceptionsHelper.convertToRuntime(e);
        }
    }

    public String authenticate(final KerberosToken token) {
        String username;

        if (token.credentials() != null && acceptorKeyTabPath != null && acceptorPrincipal != null) {
            GSSContext gssContext = null;
            byte[] outToken;
            SecurityManager securityManager = System.getSecurityManager();

            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }

            final Subject subject = this.loginUsingKeytab();

            try {
                final GSSManager manager = GSSManager.getInstance();
                GSSCredential gssCredential = AccessController.doPrivileged(new CreateCredentialAction(subject, manager));

                gssContext = manager.createContext(gssCredential);

                outToken = AccessController.doPrivileged(new AcceptAction(subject, gssContext, token.credentials()));

                if (outToken == null) {
                    logger.warn("Ticket validation not successful, outToken is null");
                    return null;
                }

                username = AccessController.doPrivileged(new AuthenticateAction(subject, logger, gssContext));

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
                throw ExceptionsHelper.convertToRuntime(cause);
            } finally {
                if (gssContext != null) {
                    try {
                        gssContext.dispose();
                    } catch (final GSSException ignored) {
                    }
                }
                //TODO subject logout
            }
            return username;
        } else {
            return null;
        }
    }

    private static class CreateCredentialAction implements PrivilegedExceptionAction<GSSCredential> {

        private final Subject subject;
        private GSSManager manager;

        CreateCredentialAction(Subject subject, GSSManager manager) {
            this.subject = subject;
            this.manager = manager;
        }

        @Override
        public GSSCredential run() throws GSSException {
            try {
                return Subject.doAs(subject, new PrivilegedExceptionAction<GSSCredential>() {
                    @Override
                    public GSSCredential run() throws GSSException {
                        return manager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, GSS_SPNEGO_MECH_OID, GSSCredential.ACCEPT_ONLY);
                    }
                });
            } catch (PrivilegedActionException e) {
                throw (GSSException) e.getException();
            }
        }
    }

    /**
     * This class gets a gss credential via a privileged action.
     */
    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AcceptAction implements PrivilegedExceptionAction<byte[]> {
        private final Subject subject;
        private final GSSContext gssContext;
        private final byte[] decoded;

        AcceptAction(Subject subject, GSSContext context, byte[] decodedToken) {
            this.subject = subject;
            this.gssContext = context;
            this.decoded = decodedToken;
        }

        @Override
        public byte[] run() throws GSSException {
            try {
                return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {
                    @Override
                    public byte[] run() throws Exception {
                        return gssContext.acceptSecContext(decoded, 0, decoded.length);
                    }
                });
            } catch (PrivilegedActionException e) {
                throw (GSSException) e.getException();
            }
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

    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AuthenticateAction implements PrivilegedAction<String> {

        private final Subject subject;
        private final ESLogger logger;
        private final GSSContext gssContext;

        private AuthenticateAction(Subject subject, ESLogger logger, GSSContext gssContext) {
            this.subject = subject;
            this.logger = logger;
            this.gssContext = gssContext;
        }

        @Override
        public String run() {
            return Subject.doAs(subject, new PrivilegedAction<String>() {
                @Override
                public String run() {
                    return getUsernameFromGSSContext(gssContext, logger);
                }
            });
        }
    }
}
