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

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.security.auth.Subject;
import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.SuppressForbidden;
import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

@SuppressForbidden(reason = "unit test")
public class MockingKerberizedClient extends KerberizedClient {

    public MockingKerberizedClient(final Client in) {
        super(in, new Subject(), "mock_principal");
    }

    @Override
    GSSContext initGSS() throws Exception {
        return new MockGSSContext();
    }

    @Override
    void addAdditionalHeader(final ActionRequest<ActionRequest> request, final int count, final byte[] data) {
        if (count >= 4) {
            request.putHeader("Authorization", "Negotiate_c " + DatatypeConverter.printBase64Binary(data));
        }
    }

    @SuppressForbidden(reason = "unit test")
    private static class MockGSSContext implements GSSContext {

        @Override
        public byte[] initSecContext(final byte[] inputBuf, final int offset, final int len) throws GSSException {
            if (inputBuf == null || inputBuf.length == 0) {
                return "mocked_initial_gss_security_context".getBytes(StandardCharsets.UTF_8);
            } else {
                return ("|" + new String(inputBuf, offset, len, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
            }
        }

        @Override
        public int initSecContext(final InputStream inStream, final OutputStream outStream) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public byte[] acceptSecContext(final byte[] inToken, final int offset, final int len) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void acceptSecContext(final InputStream inStream, final OutputStream outStream) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean isEstablished() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void dispose() throws GSSException {
        }

        @Override
        public int getWrapSizeLimit(final int qop, final boolean confReq, final int maxTokenSize) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public byte[] wrap(final byte[] inBuf, final int offset, final int len, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void wrap(final InputStream inStream, final OutputStream outStream, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");

        }

        @Override
        public byte[] unwrap(final byte[] inBuf, final int offset, final int len, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void unwrap(final InputStream inStream, final OutputStream outStream, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public byte[] getMIC(final byte[] inMsg, final int offset, final int len, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void getMIC(final InputStream inStream, final OutputStream outStream, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void verifyMIC(final byte[] inToken, final int tokOffset, final int tokLen, final byte[] inMsg, final int msgOffset,
                final int msgLen, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void verifyMIC(final InputStream tokStream, final InputStream msgStream, final MessageProp msgProp) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public byte[] export() throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestMutualAuth(final boolean state) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestReplayDet(final boolean state) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestSequenceDet(final boolean state) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestCredDeleg(final boolean state) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestAnonymity(final boolean state) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestConf(final boolean state) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestInteg(final boolean state) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void requestLifetime(final int lifetime) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public void setChannelBinding(final ChannelBinding cb) throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean getCredDelegState() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean getMutualAuthState() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean getReplayDetState() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean getSequenceDetState() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean getAnonymityState() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean isTransferable() throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean isProtReady() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean getConfState() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean getIntegState() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public int getLifetime() {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public GSSName getSrcName() throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public GSSName getTargName() throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public Oid getMech() throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public GSSCredential getDelegCred() throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }

        @Override
        public boolean isInitiator() throws GSSException {
            throw new UnsupportedOperationException("mock gss context does not support this operation");
        }
    }
}
