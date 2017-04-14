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
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm.support;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.shield.authc.RealmConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class PropertyUtil {

    private static final String KRB5_FILE_PATH = "files.krb5_conf";
    private final Path krb5ConfPath;

    public PropertyUtil(RealmConfig config) {
        String krb5Conf = config.settings().get(KRB5_FILE_PATH, null);

        if (krb5Conf == null) {
            throw new ElasticsearchException("Unconfigured (but required) property: {}", KRB5_FILE_PATH);
        }

        krb5ConfPath = config.env().configFile().resolve(krb5Conf).toAbsolutePath();
    }

    public void initKerberosProperty() {
        SecurityManager securityManager = System.getSecurityManager();

        if (securityManager != null) {
            securityManager.checkPermission(new SpecialPermission());
        }

        if (!Files.isReadable(krb5ConfPath) || Files.isDirectory(krb5ConfPath)) {
            throw new ElasticsearchException("File not found or not readable: {}", krb5ConfPath);
        }

        AccessController.doPrivileged(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return System.setProperty("java.security.krb5.conf", String.valueOf(krb5ConfPath));
            }
        });
    }
}
