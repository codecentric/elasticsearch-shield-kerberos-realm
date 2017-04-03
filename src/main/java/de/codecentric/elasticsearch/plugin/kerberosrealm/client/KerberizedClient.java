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
import org.elasticsearch.action.*;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.FilterClient;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Objects;

import static de.codecentric.elasticsearch.plugin.kerberosrealm.support.GSSUtil.GSS_SPNEGO_MECH_OID;

/**
 * @author salyh
 */
public class KerberizedClient extends FilterClient {

    private final ESLogger logger = Loggers.getLogger(this.getClass());
    private final Subject initiatorSubject;
    private final String acceptorPrincipal;

    public KerberizedClient(Client in, String principal, String password, String acceptorPrincipal) throws LoginException {
        super(in);
        this.initiatorSubject = JaasKrbUtil.loginUsingPassword(principal, password);
        this.acceptorPrincipal = Objects.requireNonNull(acceptorPrincipal);
    }

    @Override
    protected <Request extends ActionRequest, Response extends ActionResponse, RequestBuilder extends ActionRequestBuilder<Request, Response, RequestBuilder>> void doExecute(
            Action<Request, Response, RequestBuilder> action, Request request, ActionListener<Response> listener) {

        GSSContext context;
        try {
            context = initGSS();
            //TODO subject logout
        } catch (GSSException | PrivilegedActionException e) {
            logger.error("Error creating gss context {}", e, e.toString());
            listener.onFailure(e);
            return;
        }

        if (request.getHeader("Authorization") == null) {
            byte[] data;
            try {
                data = context.initSecContext(new byte[0], 0, 0);
                //TODO subject logout
            } catch (GSSException e) {
                logger.error("Error creating gss context {}", e, e.toString());
                listener.onFailure(e);
                return;
            }

            request.putHeader("Authorization", "Negotiate " + DatatypeConverter.printBase64Binary(data));
            logger.debug("Initial gss context round");
        } else {
            logger.debug("Non-Initial gss context round: {}", request.getHeader("Authorization"));
        }

        super.doExecute(action, request, listener);
    }

    private GSSContext initGSS() throws PrivilegedActionException, GSSException {
        final GSSManager manager = GSSManager.getInstance();

        PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
            @Override
            public GSSCredential run() throws GSSException {
                return manager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, GSS_SPNEGO_MECH_OID, GSSCredential.INITIATE_ONLY);
            }
        };

        GSSCredential clientcreds = Subject.doAs(initiatorSubject, action);

        GSSContext context = manager.createContext(manager.createName(acceptorPrincipal, GSSName.NT_USER_NAME, GSS_SPNEGO_MECH_OID),
                GSS_SPNEGO_MECH_OID, clientcreds, GSSContext.DEFAULT_LIFETIME);

        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);
        context.requestReplayDet(true);
        context.requestSequenceDet(true);
        context.requestCredDeleg(false);

        return context;
    }
}
