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

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;

public class SettingConstants {

    private static final String PREFIX = "de.codecentric.realm." + KerberosRealm.TYPE + ".";
    //public static final String JAAS_LOGIN_CONF_FILE_PATH = "jaas_login_conf.file_path";
    public static final String STRIP_REALM_FROM_PRINCIPAL = "strip_realm_from_principal";
    public static final String ACCEPTOR_KEYTAB_PATH = "acceptor_keytab_path";
    public static final String ACCEPTOR_PRINCIPAL = "acceptor_principal";
    public static final String ROLES = "roles";

    public static final String KRB_DEBUG = PREFIX + "krb_debug";
    public static final String KRB5_FILE_PATH = PREFIX + "krb5.file_path";
    
    public static final String LDAP_URL = "ldap_url";
    public static final String LDAP_DOMAIN = "ldap_domain";
    public static final String LDAP_GROUP_BASE = "ldap_group_base";
    public static final String LDAP_USER = "ldap_user";
    public static final String LDAP_PASSWORD = "ldap_password";
    
    public static final String KEYSTORE_PATH = "shield.ssl.keystore.path";
    public static final String KEYSTORE_PASSWORD = "shield.ssl.keystore.password";
    
            

    private SettingConstants() {

    }

}
