package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public class KerberosAuthenticatorTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Rule
    public ExpectedException expectedExcpetion = ExpectedException.none();

    private Settings globalSettings;

    @Before
    public void before() {
        globalSettings = Settings.builder()
                .put("path.home", temporaryFolder.getRoot().getAbsolutePath())
                .build();
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_principal_is_missing() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_principal");

        Settings realmSettings = Settings.builder()
                .put("acceptor_keytab_path", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_path_is_missing() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_keytab_path");

        Settings realmSettings = Settings.builder()
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_is_not_readable() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        Settings realmSettings = Settings.builder()
                .put("acceptor_keytab_path", "")
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_is_a_directory() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        Settings realmSettings = Settings.builder()
                .put("acceptor_keytab_path", temporaryFolder.getRoot().getAbsolutePath())
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_not_authenticate_empty_token() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        Settings realmSettings = Settings.builder()
                .put("acceptor_keytab_path", temporaryFolder.getRoot().getAbsolutePath())
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }
}
