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
package de.codecentric.elasticsearch.plugin.kerberosrealm.support;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public class KrbConstants {

    static {
        Oid spnegoTmp = null;
        try {
            spnegoTmp = new Oid("1.3.6.1.5.5.2");
        } catch (final GSSException e) {

        }
        SPNEGO = spnegoTmp;
    }

    public static final Oid SPNEGO;
    public static final String KRB5_CONF_PROP = "java.security.krb5.conf";
    public static final String JAAS_LOGIN_CONF_PROP = "java.security.auth.login.config";
    public static final String USE_SUBJECT_CREDS_ONLY_PROP = "javax.security.auth.useSubjectCredsOnly";
    public static final String NEGOTIATE = "Negotiate";
    public static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private KrbConstants() {
    }

}
