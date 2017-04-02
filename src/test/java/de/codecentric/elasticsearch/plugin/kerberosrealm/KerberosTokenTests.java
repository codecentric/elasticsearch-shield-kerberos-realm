package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosToken;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class KerberosTokenTests {

    @Test
    public void should_be_valid_with_non_empty_principal() {
        KerberosToken token = new KerberosToken(new byte[0], "principal");

        assertThat(token.isValid(), is(true));
    }

    @Test
    public void should_be_invalid_with_empty_principal() {
        KerberosToken token = new KerberosToken(new byte[0], "");

        assertThat(token.isValid(), is(false));
    }

    @Test
    public void should_have_no_credentials_after_clearing_credentials() {
        KerberosToken token = new KerberosToken(new byte[0], "principal");
        token.clearCredentials();

        assertThat(token.credentials(), is(nullValue()));
    }

    @Test
    public void should_be_invalid_after_clearing_credentials() {
        KerberosToken token = new KerberosToken(new byte[0], "principal");
        token.clearCredentials();

        assertThat(token.isValid(), is(false));
    }
}
