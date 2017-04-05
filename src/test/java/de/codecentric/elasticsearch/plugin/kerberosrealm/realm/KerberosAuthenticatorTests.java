package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.test.ESTestCase;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.file.Path;

public class KerberosAuthenticatorTests extends ESTestCase {

    @Rule
    public ExpectedException expectedExcpetion = ExpectedException.none();

    private Path tempDirPath;
    private Settings globalSettings;

    @Before
    public void before() {
        tempDirPath = createTempDir("tempdir-unittest");
        globalSettings = Settings.builder().put("path.home", tempDirPath).build();
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
                .put("acceptor_keytab_path", tempDirPath.toAbsolutePath())
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }
}
