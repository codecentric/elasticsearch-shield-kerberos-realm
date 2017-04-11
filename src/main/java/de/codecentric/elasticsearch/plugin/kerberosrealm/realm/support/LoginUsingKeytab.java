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

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

public class LoginUsingKeytab {

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";
    static boolean ENABLE_DEBUG = false;
    private final KeytabConfiguration configuration;

    public LoginUsingKeytab(String principal, Path keytabPath) throws LoginException {
        configuration = new KeytabConfiguration(principal, keytabPath);
    }

    public Subject login() throws LoginException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Subject>() {
                @Override
                public Subject run() throws LoginException {
                    LoginContext loginContext = new LoginContext("KeytabConfiguration", null, null, configuration);

                    loginContext.login();
                    return loginContext.getSubject();
                }
            });
        } catch (PrivilegedActionException e) {
            throw  (LoginException) e.getException();
        }
    }

    private static class KeytabConfiguration extends Configuration {
        private final String principal;
        private final Path keytabPath;

        KeytabConfiguration(String principal, Path keytab) {
            this.principal = principal;
            this.keytabPath = keytab;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<>();
            options.put("keyTab", keytabPath.toAbsolutePath().toString());
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("isInitiator", "false");
            options.put("renewTGT", "false");
            options.put("refreshKrb5Config", "true");
            options.put("debug", String.valueOf(ENABLE_DEBUG));

            return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(KRB5_LOGIN_MODULE, LoginModuleControlFlag.REQUIRED, options)
            };
        }
    }
}
