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

   Author: Kerby Project, Apache Software Foundation, https://directory.apache.org/kerby/
 */
package com.tngtech.elasticsearch.plugin.kerberosrealm.support;

//taken from the apache kerby project
//https://directory.apache.org/kerby/

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JAAS utilities for Kerberos login.
 */
public final class JaasKrbUtil {

    static boolean ENABLE_DEBUG = false;

    private JaasKrbUtil() {
    }

    public static Subject loginUsingPassword(final String principal, final String password) throws LoginException {
        final Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));

        final Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());

        final Configuration conf = usePassword(principal);
        final String confName = "PasswordConf";
        final CallbackHandler callback = new KrbCallbackHandler(principal, password);
        final LoginContext loginContext = new LoginContext(confName, subject, callback, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    public static Subject loginUsingTicketCache(final String principal, final Path cachePath) throws LoginException {
        final Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));

        final Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());

        final Configuration conf = useTicketCache(principal, cachePath);
        final String confName = "TicketCacheConf";
        final LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    public static Subject loginUsingKeytab(final String principal, final Path keytabPath, final boolean initiator) throws LoginException {
        final Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));

        final Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());

        final Configuration conf = useKeytab(principal, keytabPath, initiator);
        final String confName = "KeytabConf";
        final LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    private static Configuration usePassword(final String principal) {
        return new PasswordJaasConf(principal);
    }

    private static Configuration useTicketCache(final String principal, final Path credentialPath) {
        return new TicketCacheJaasConf(principal, credentialPath);
    }

    private static Configuration useKeytab(final String principal, final Path keytabPath, final boolean initiator) {
        return new KeytabJaasConf(principal, keytabPath, initiator);
    }

    private static String getKrb5LoginModuleName() {
        return System.getProperty("java.vendor").contains("IBM") ? "com.ibm.security.auth.module.Krb5LoginModule"
                : "com.sun.security.auth.module.Krb5LoginModule";
    }

    static class KeytabJaasConf extends Configuration {
        private final String principal;
        private final Path keytabPath;
        private final boolean initiator;

        KeytabJaasConf(final String principal, final Path keytab, final boolean initiator) {
            this.principal = principal;
            this.keytabPath = keytab;
            this.initiator = initiator;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
            final Map<String, String> options = new HashMap<>();
            options.put("keyTab", keytabPath.toAbsolutePath().toString());
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("renewTGT", "false");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", String.valueOf(initiator));
            options.put("debug", String.valueOf(ENABLE_DEBUG));

            return new AppConfigurationEntry[] { new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
        }
    }

    static class TicketCacheJaasConf extends Configuration {
        private final String principal;
        private final Path clientCredentialPath;

        TicketCacheJaasConf(final String principal, final Path clientCredentialPath) {
            this.principal = principal;
            this.clientCredentialPath = clientCredentialPath;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
            final Map<String, String> options = new HashMap<>();
            options.put("principal", principal);
            options.put("storeKey", "false");
            options.put("doNotPrompt", "false");
            options.put("useTicketCache", "true");
            options.put("renewTGT", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "true");
            options.put("ticketCache", clientCredentialPath.toAbsolutePath().toString());
            options.put("debug", String.valueOf(ENABLE_DEBUG));

            return new AppConfigurationEntry[] { new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
        }
    }

    static class PasswordJaasConf extends Configuration {
        private final String principal;

        PasswordJaasConf(final String principal) {
            this.principal = principal;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
            final Map<String, String> options = new HashMap<>();
            options.put("principal", principal);
            options.put("storeKey", "true");
            options.put("useTicketCache", "true");
            options.put("useKeyTab", "false");
            options.put("renewTGT", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "true");
            options.put("debug", String.valueOf(ENABLE_DEBUG));

            return new AppConfigurationEntry[] { new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
        }
    }

    public static class KrbCallbackHandler implements CallbackHandler {
        private final String principal;
        private final String password;

        KrbCallbackHandler(final String principal, final String password) {
            this.principal = principal;
            this.password = password;
        }

        @Override
        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    final PasswordCallback pc = (PasswordCallback) callback;
                    if (pc.getPrompt().contains(principal)) {
                        pc.setPassword(password.toCharArray());
                        break;
                    }
                }
            }
        }
    }

}
