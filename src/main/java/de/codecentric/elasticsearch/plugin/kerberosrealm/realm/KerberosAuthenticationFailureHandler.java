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
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.DefaultAuthenticationFailureHandler;
import org.elasticsearch.transport.TransportMessage;

import de.codecentric.elasticsearch.plugin.kerberosrealm.support.KrbConstants;

/**
 */
public class KerberosAuthenticationFailureHandler extends DefaultAuthenticationFailureHandler {

    protected final ESLogger logger = Loggers.getLogger(this.getClass());

    @Override
    public ElasticsearchSecurityException unsuccessfulAuthentication(final RestRequest request, final AuthenticationToken token) {
        final ElasticsearchSecurityException e = super.unsuccessfulAuthentication(request, token);
        e.addHeader(KrbConstants.WWW_AUTHENTICATE, KrbConstants.NEGOTIATE);
        if (logger.isDebugEnabled()) {
            logger.debug("unsuccessfulAuthentication for rest request and token {}", token);
        }
        return e;
    }

    @Override
    public ElasticsearchSecurityException missingToken(final RestRequest request) {
        final ElasticsearchSecurityException e = super.missingToken(request);
        e.addHeader(KrbConstants.WWW_AUTHENTICATE, KrbConstants.NEGOTIATE);
        if (logger.isDebugEnabled()) {
            logger.debug("missing token for rest request");
        }
        return e;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(final RestRequest request, final Exception e) {
        final ElasticsearchSecurityException se = super.exceptionProcessingRequest(request, e);
        String outToken = "";
        if (e instanceof ElasticsearchException) {
            final ElasticsearchException kae = (ElasticsearchException) e;
            if (kae.getHeader("kerberos_out_token") != null) {
                outToken = " " + kae.getHeader("kerberos_out_token").get(0);
            }
        }

        se.addHeader(KrbConstants.WWW_AUTHENTICATE, KrbConstants.NEGOTIATE + outToken);

        if (logger.isDebugEnabled()) {
            logger.debug("exception for rest request: {}", e.toString());
        }

        return se;
    }

    @Override
    public ElasticsearchSecurityException authenticationRequired(final String action) {
        final ElasticsearchSecurityException se = super.authenticationRequired(action);
        se.addHeader(KrbConstants.WWW_AUTHENTICATE, KrbConstants.NEGOTIATE);

        if (logger.isDebugEnabled()) {
            logger.debug("authentication required for action {}", action);
        }
        return se;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(final TransportMessage message, final Exception e) {
        final ElasticsearchSecurityException se = super.exceptionProcessingRequest(message, e);
        String outToken = "";

        if (e instanceof ElasticsearchException) {
            final ElasticsearchException kae = (ElasticsearchException) e;
            if (kae.getHeader("kerberos_out_token") != null) {
                outToken = " " + kae.getHeader("kerberos_out_token").get(0);
            }
        }
        se.addHeader(KrbConstants.WWW_AUTHENTICATE, KrbConstants.NEGOTIATE + outToken);

        if (logger.isDebugEnabled()) {
            logger.debug("exception for transport message: {}", e.toString());
        }

        return se;
    }

    @Override
    public ElasticsearchSecurityException missingToken(final TransportMessage message, final String action) {
        final ElasticsearchSecurityException se = super.missingToken(message, action);
        se.addHeader(KrbConstants.WWW_AUTHENTICATE, KrbConstants.NEGOTIATE);

        if (logger.isDebugEnabled()) {
            logger.debug("missing token for {} transport message", action);
        }

        return se;
    }

    @Override
    public ElasticsearchSecurityException unsuccessfulAuthentication(final TransportMessage message, final AuthenticationToken token,
            final String action) {
        final ElasticsearchSecurityException se = super.unsuccessfulAuthentication(message, token, action);
        se.addHeader(KrbConstants.WWW_AUTHENTICATE, KrbConstants.NEGOTIATE);

        if (logger.isDebugEnabled()) {
            logger.debug("unsuccessfulAuthentication for {} transport message and token {}", action, token);
        }

        return se;
    }

}
