package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.test.ESTestCase;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.file.Path;

public class KerberosRealmTests extends ESTestCase {

    @Rule
    public ExpectedException expectedExcpetion = ExpectedException.none();

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_principal_is_missing() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_principal");

        Settings globalSettings = Settings.builder().put("path.home", createTempDir()).build();
        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_keytab_path", "")
                .build();
        new KerberosRealm(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_path_is_missing() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_keytab_path");

        Settings globalSettings = Settings.builder().put("path.home", createTempDir()).build();
        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_principal", "")
                .build();
        new KerberosRealm(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_is_not_readable() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        Settings globalSettings = Settings.builder().put("path.home", createTempDir()).build();
        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_keytab_path", "")
                .put("acceptor_principal", "")
                .build();
        new KerberosRealm(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_not_throw_elasticsearch_exception_when_acceptor_keytab_is_a_directory() {
        Path tempDir = createTempDir();
        Settings globalSettings = Settings.builder().put("path.home", tempDir).build();
        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_keytab_path", tempDir.toAbsolutePath())
                .put("acceptor_principal", "")
                .build();
        new KerberosRealm(new RealmConfig("test", realmSettings, globalSettings));
    }
}
