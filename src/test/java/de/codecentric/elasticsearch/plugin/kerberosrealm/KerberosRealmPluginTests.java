package de.codecentric.elasticsearch.plugin.kerberosrealm;

import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class KerberosRealmPluginTests {

    @Test
    public void should_return_its_name() {
        KerberosRealmPlugin realmPlugin = new KerberosRealmPlugin(Settings.EMPTY);

        assertThat(realmPlugin.name(), is("cc-kerberos-realm"));
    }

    @Test
    public void should_return_its_description() {
        KerberosRealmPlugin realmPlugin = new KerberosRealmPlugin(Settings.EMPTY);

        assertThat(realmPlugin.description(), is("codecentric AG Kerberos V5 Realm"));
    }

    @Test
    public void should_not_add_a_kerberos_realm_for_client_nodes() {
        Settings settings = Settings.builder().put("client.type", true).build();
        KerberosRealmPlugin realmPlugin = new KerberosRealmPlugin(settings);

        realmPlugin.onModule(null);
    }
}
