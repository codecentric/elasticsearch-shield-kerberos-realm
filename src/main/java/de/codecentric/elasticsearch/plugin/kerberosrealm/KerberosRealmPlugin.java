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
package de.codecentric.elasticsearch.plugin.kerberosrealm;

import java.nio.file.Paths;

import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestModule;
import org.elasticsearch.shield.authc.AuthenticationModule;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosAuthenticationFailureHandler;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealmFactory;
import de.codecentric.elasticsearch.plugin.kerberosrealm.rest.LoginInfoRestAction;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.PropertyUtil;

/**
 */
public class KerberosRealmPlugin extends Plugin {

    protected final ESLogger logger = Loggers.getLogger(this.getClass());
    private static final String CLIENT_TYPE = "client.type";
    private final boolean client;
    private final Settings settings;

    public KerberosRealmPlugin(final Settings settings) {
        this.settings = settings;
        client = !"node".equals(settings.get(CLIENT_TYPE, "node"));
        logger.info("Start Kerberos Realm Plugin (mode: {})", settings.get(CLIENT_TYPE));
    }

    @Override
    public String name() {
        return KerberosRealm.TYPE + "-realm";
    }

    @Override
    public String description() {
        return "codecentric AG Kerberos V5 Realm";
    }
    
    public void onModule(final RestModule module) {
        if (!client) {
            module.addRestAction(LoginInfoRestAction.class);
        }
    }

    @SuppressForbidden(reason = "proper use of Paths.get()")
    public void onModule(final AuthenticationModule authenticationModule) {
        if (!client) {
            PropertyUtil.initKerberosProps(settings, Paths.get("/"));
            authenticationModule.addCustomRealm(KerberosRealm.TYPE, KerberosRealmFactory.class);
            authenticationModule.setAuthenticationFailureHandler(KerberosAuthenticationFailureHandler.class);
        } else {
            logger.warn("This plugin is not necessary for client nodes");
        }
    }
}
