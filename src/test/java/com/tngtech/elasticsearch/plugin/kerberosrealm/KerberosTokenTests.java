package com.tngtech.elasticsearch.plugin.kerberosrealm;

import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.KerberosToken;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class KerberosTokenTests {

    @Test
    public void should_be_valid_with_non_empty_principal() {
        KerberosToken token = new KerberosToken(new byte[0], "principal");

        assertEquals(true, token.isValid());
    }

    @Test
    public void should_be_invalid_with_empty_principal() {
        KerberosToken token = new KerberosToken(new byte[0], "");

        assertEquals(false, token.isValid());
    }

    @Test
    public void should_have_no_credentials_after_clearing_credentials() {
        KerberosToken token = new KerberosToken(new byte[0], "principal");
        token.clearCredentials();

        assertEquals(null, token.credentials());
    }

    @Test
    public void should_be_invalid_after_clearing_credentials() {
        KerberosToken token = new KerberosToken(new byte[0], "principal");
        token.clearCredentials();

        assertEquals(false, token.isValid());
    }
}
