package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosToken.KerberosTokenFactory;
import org.elasticsearch.ElasticsearchException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.xml.bind.DatatypeConverter;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;

public class KerberosTokenTests {

    @Rule
    public ExpectedException expectedExcpetion = ExpectedException.none();

    @Test
    public void should_have_no_credentials_after_clearing_credentials() {
        KerberosToken token = new KerberosToken(new byte[0]);
        token.clearCredentials();

        assertThat(token.credentials(), is(nullValue()));
    }

    @Test
    public void should_return_no_principal() {
        KerberosToken token = new KerberosToken(new byte[0]);

        assertThat(token.principal(), is(nullValue()));
    }

    @Test
    public void should_not_create_a_token_when_header_is_null() {
        assertThat(new KerberosTokenFactory().extractToken(null), is(nullValue()));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_header_not_start_with_negotiate() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Bad 'Authorization' header");

        new KerberosTokenFactory().extractToken("something");
    }

    @Test
    public void should_return_a_token() {
        byte[] expectedToken = new byte[]{1, 2, 3};
        String header = "Negotiate " + DatatypeConverter.printBase64Binary(expectedToken);

        KerberosToken token = new KerberosTokenFactory().extractToken(header);

        assertArrayEquals(token.credentials(), expectedToken);
    }
}