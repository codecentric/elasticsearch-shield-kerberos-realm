package de.codecentric.elasticsearch.plugin.kerberosrealm;

import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

public class KerberosRealmPluginTests {

    @Test
    public void should_return_the_name() {
        KerberosRealmPlugin realmPlugin = new KerberosRealmPlugin(Settings.EMPTY);

    }
}
