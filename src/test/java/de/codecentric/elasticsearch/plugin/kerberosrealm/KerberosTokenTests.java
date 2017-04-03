package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosToken;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class KerberosTokenTests {

    @Test
    public void should_have_no_credentials_after_clearing_credentials() {
        KerberosToken token = new KerberosToken(new byte[0]);
        token.clearCredentials();

        assertThat(token.credentials(), is(nullValue()));
    }
}
