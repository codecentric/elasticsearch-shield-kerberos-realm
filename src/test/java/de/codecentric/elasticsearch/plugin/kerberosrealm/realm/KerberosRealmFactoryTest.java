package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class KerberosRealmFactoryTest {

    @Test
    public void should_not_create_a_kerberos_realm_without_any_config() {
        KerberosRealmFactory realmFactory = new KerberosRealmFactory(null);

        assertThat(realmFactory.createDefault(null), is(nullValue()));
    }
}
