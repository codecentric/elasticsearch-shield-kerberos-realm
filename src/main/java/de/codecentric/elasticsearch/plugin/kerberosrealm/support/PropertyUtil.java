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

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

public class PropertyUtil {

    private static final ESLogger log = Loggers.getLogger(PropertyUtil.class);

    private PropertyUtil() {
    }

    @SuppressForbidden(reason = "sysout needed here cause krb debug also goes to sysout")
    public static void initKerberosProps(final Settings settings, Path conf) {
        if (conf == null) {
            final Environment env = new Environment(settings);
            conf = env.configFile();
        }
        PropertyUtil.setSystemProperty(KrbConstants.USE_SUBJECT_CREDS_ONLY_PROP, "false", false);
        //PropertyUtil.setSystemProperty(KrbConstants.USE_SUBJECT_CREDS_ONLY_PROP, "true", false); //TODO make strict
        try {
            PropertyUtil.setSystemPropertyToRelativeFile(KrbConstants.KRB5_CONF_PROP, conf,
                    settings.get(SettingConstants.KRB5_FILE_PATH, "/etc/krb5.conf"), false, true);
        } catch (final FileNotFoundException e) {
            ExceptionsHelper.convertToElastic(e);
        }

        final boolean krbDebug = settings.getAsBoolean(SettingConstants.KRB_DEBUG, false);

        if (krbDebug) {
            System.out.println("Kerberos Realm debug is enabled");
            log.error("NOT AN ERROR: Kerberos Realm debug is enabled");
            JaasKrbUtil.ENABLE_DEBUG = true;
            System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.debug", "all");
            System.setProperty("java.security.auth.debug", "all");
            System.setProperty("sun.security.spnego.debug", "true");
        } else {
            log.info("Kerberos Realm debug is disabled");
        }

        log.info(KrbConstants.KRB5_CONF_PROP + ": {}", System.getProperty(KrbConstants.KRB5_CONF_PROP));

    }

    public static boolean setSystemPropertyToRelativeFile(final String property, final Path parentDir, final String relativeFileName,
            final boolean overwrite, final boolean checkFileExists) throws FileNotFoundException {
        if (relativeFileName == null) {
            log.error("Cannot set property " + property + " because filename is null");
            return false;
        }
        final Path path = parentDir.resolve(relativeFileName).toAbsolutePath();

        if (Files.isReadable(path) && !Files.isDirectory(path)) {
            return setSystemProperty(property, path.toString(), overwrite);
        } else {

            if (checkFileExists) {
                throw new FileNotFoundException(path.toString());
            }

            log.error("Cannot read from {}, maybe the file does not exists? ", path.toString());
        }
        return false;
    }

    public static boolean setSystemProperty(final String property, final String value, final boolean overwrite) {
        if (System.getProperty(property) == null) {
            if (value == null) {
                log.error("Cannot set property " + property + " because value is null");
                return false;
            }
            log.info("Set system property {} to {}", property, value);
            System.setProperty(property, value);
            return true;
        } else {
            log.warn("Property " + property + " already set to " + System.getProperty(property));
            if (overwrite) {
                log.info("Overwrite system property {} with {} (old value was {})", property, value, System.getProperty(property));
                System.setProperty(property, value);
                return true;
            }
        }
        return false;
    }
}
