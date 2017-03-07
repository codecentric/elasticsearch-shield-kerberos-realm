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
package de.codecentric.elasticsearch.plugin.kerberosrealm.client;

import de.codecentric.elasticsearch.plugin.kerberosrealm.support.JaasKrbUtil;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.KrbConstants;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.PropertyUtil;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.*;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.FilterClient;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * 
 * @author salyh
 *
 */
public class KerberizedClient extends FilterClient {

    private final ESLogger logger = Loggers.getLogger(this.getClass());
    private final Subject initiatorSubject;
    private final String acceptorPrincipal;

    /**
     * 
     * @param in
     * @param initiatorSubject
     * @param acceptorPrincipal
     */
    @SuppressForbidden(reason = "only used external")
    public KerberizedClient(final Client in, final Subject initiatorSubject, final String acceptorPrincipal) {
        super(in);
        PropertyUtil.initKerberosProps(settings, Paths.get("/"));
        this.initiatorSubject = Objects.requireNonNull(initiatorSubject);
        this.acceptorPrincipal = Objects.requireNonNull(acceptorPrincipal);
    }

    /**
     * 
     * @param in
     * @param initiatorPrincipal
     * @param tgtTicketCache
     *            make sure youre allowed to read from here es sec man
     * @param acceptorPrincipal
     * @throws LoginException
     */
    public KerberizedClient(final Client in, final String initiatorPrincipal, final Path tgtTicketCache, final String acceptorPrincipal)
            throws LoginException {
        this(in, JaasKrbUtil.loginUsingTicketCache(initiatorPrincipal, tgtTicketCache), acceptorPrincipal);
    }

    /**
     * 
     * @param in
     * @param initiatorPrincipal
     * @param initiatorPrincipalPassword
     * @param acceptorPrincipal
     * @throws LoginException
     */
    public KerberizedClient(final Client in, final String initiatorPrincipal, final String initiatorPrincipalPassword,
            final String acceptorPrincipal) throws LoginException {
        this(in, JaasKrbUtil.loginUsingPassword(initiatorPrincipal, initiatorPrincipalPassword), acceptorPrincipal);
    }

    /**
     * 
     * @param in
     * @param keyTabFile
     * @param initiatorPrincipal
     * @param acceptorPrincipal
     * @throws LoginException
     */
    public KerberizedClient(final Client in, final Path keyTabFile, final String initiatorPrincipal, final String acceptorPrincipal)
            throws LoginException {
        this(in, JaasKrbUtil.loginUsingKeytab(initiatorPrincipal, keyTabFile, true), acceptorPrincipal);
    }

    @Override
    protected final <Request extends ActionRequest, Response extends ActionResponse, RequestBuilder extends ActionRequestBuilder<Request, Response, RequestBuilder>> void doExecute(
            final Action<Request, Response, RequestBuilder> action, final Request request, final ActionListener<Response> listener) {

        GSSContext context;
        try {
            context = initGSS();
            //TODO subject logout
        } catch (final Exception e) {
            logger.error("Error creating gss context {}", e, e.toString());
            listener.onFailure(e);
            return;
        }

        if (request.getHeader("Authorization") == null) {

            byte[] data;
            try {
                data = context.initSecContext(new byte[0], 0, 0);
                //TODO subject logout
            } catch (final Exception e) {
                logger.error("Error creating gss context {}", e, e.toString());
                listener.onFailure(e);
                return;
            }

            request.putHeader("Authorization", "Negotiate " + DatatypeConverter.printBase64Binary(data));
            logger.debug("Initial gss context round");
        } else {
            logger.debug("Non-Initial gss context round: {}", request.getHeader("Authorization"));
        }

        final ActionListener<Response> newListener = (ActionListener<Response>) ((listener instanceof KerberosActionListener) ? listener
                : new KerberosActionListener(listener, action, request, context));

        super.doExecute(action, request, newListener);
    }

    void addAdditionalHeader(final ActionRequest<ActionRequest> request, final int count, final byte[] data) {

    }

    GSSContext initGSS() throws Exception {
        final GSSManager MANAGER = GSSManager.getInstance();

        final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
            @Override
            public GSSCredential run() throws GSSException {
                return MANAGER.createCredential(null, GSSCredential.DEFAULT_LIFETIME, KrbConstants.SPNEGO, GSSCredential.INITIATE_ONLY);
            }
        };

        final GSSCredential clientcreds = Subject.doAs(initiatorSubject, action);

        final GSSContext context = MANAGER.createContext(MANAGER.createName(acceptorPrincipal, GSSName.NT_USER_NAME, KrbConstants.SPNEGO),
                KrbConstants.SPNEGO, clientcreds, GSSContext.DEFAULT_LIFETIME);

        //TODO make configurable
        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);
        context.requestReplayDet(true);
        context.requestSequenceDet(true);
        context.requestCredDeleg(false);

        return context;
    }

    private class KerberosActionListener implements ActionListener<ActionResponse> {
        private final ActionListener inner;
        private final Action action;
        private final ActionRequest<ActionRequest> request;
        private final GSSContext context;
        private volatile int count;

        private KerberosActionListener(final ActionListener inner, final Action action, final ActionRequest<ActionRequest> request,
                final GSSContext context) {
            super();
            this.inner = inner;
            this.action = action;
            this.request = request;
            this.context = context;
        }

        @Override
        public void onResponse(final ActionResponse response) {
            inner.onResponse(response);
        }

        @Override
        public void onFailure(final Throwable e) {

            final Throwable cause = ExceptionsHelper.unwrapCause(e);

            if (cause instanceof ElasticsearchSecurityException) {
                final ElasticsearchSecurityException securityException = (ElasticsearchSecurityException) cause;

                if (++count > 100) {
                    inner.onFailure(new ElasticsearchException("kerberos loop", cause));
                    return;
                } else {
                    String negotiateHeaderValue = null;
                    final List<String> headers = securityException.getHeader(KrbConstants.WWW_AUTHENTICATE);
                    if (headers == null || headers.isEmpty()) {
                        inner.onFailure(new ElasticsearchException("no auth header", cause));
                        return;
                    } else if (headers.size() == 1) {
                        negotiateHeaderValue = headers.get(0).trim();
                    } else {
                        for (final String header : headers) {
                            if (header != null && header.toLowerCase(Locale.ENGLISH).startsWith(KrbConstants.NEGOTIATE)) {
                                negotiateHeaderValue = header.trim();
                                break;
                            }
                        }
                    }

                    if (negotiateHeaderValue == null) {
                        inner.onFailure(new ElasticsearchException("no negotiate auth header"));
                        return;
                    }

                    byte[] challenge = null;

                    try {
                        if (negotiateHeaderValue.length() > (KrbConstants.NEGOTIATE.length() + 1)) {
                            challenge = DatatypeConverter
                                    .parseBase64Binary(negotiateHeaderValue.substring(KrbConstants.NEGOTIATE.length() + 2));
                        }

                        byte[] data = null;

                        if (challenge == null) {
                            logger.debug("challenge is null");
                            data = context.initSecContext(new byte[0], 0, 0);
                            request.putHeader("Authorization", "Negotiate " + DatatypeConverter.printBase64Binary(data));

                        } else {
                            logger.debug("challenge is not null");
                            data = context.initSecContext(challenge, 0, challenge.length);
                            request.putHeader("Authorization", "Negotiate " + DatatypeConverter.printBase64Binary(data));
                            addAdditionalHeader(request, count, data);
                        }

                        KerberizedClient.this.doExecute(action, request, this);

                    } catch (final Exception e1) {
                        inner.onFailure(e);
                    }
                }
            } else {
                inner.onFailure(e);
            }
        }

    }
}
