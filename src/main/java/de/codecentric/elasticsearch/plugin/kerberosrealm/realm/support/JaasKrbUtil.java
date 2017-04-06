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
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm.support;

//taken from the apache kerby project
//https://directory.apache.org/kerby/

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.nio.file.Path;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JAAS utilities for Kerberos login.
 */
public class JaasKrbUtil {

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";
    static boolean ENABLE_DEBUG = false;

    public Subject loginUsingKeytab(final String principal, final Path keytabPath) throws LoginException {
        final Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));

        final Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());

        final Configuration conf = new KeytabJaasConf(principal, keytabPath);
        final String confName = "KeytabConf";
        final LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    private static class KeytabJaasConf extends Configuration {
        private final String principal;
        private final Path keytabPath;

        KeytabJaasConf(final String principal, final Path keytab) {
            this.principal = principal;
            this.keytabPath = keytab;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            final Map<String, String> options = new HashMap<>();
            options.put("keyTab", keytabPath.toAbsolutePath().toString());
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("renewTGT", "false");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "false");
            options.put("debug", String.valueOf(ENABLE_DEBUG));

            return new AppConfigurationEntry[]{new AppConfigurationEntry(KRB5_LOGIN_MODULE,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)};
        }
    }
}
