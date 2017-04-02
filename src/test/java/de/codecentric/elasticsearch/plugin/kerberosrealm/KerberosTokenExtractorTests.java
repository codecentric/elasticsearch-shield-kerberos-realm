package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosTokenExtractor;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertEquals;

@SuppressForbidden(reason = "unit tests")
public class KerberosTokenExtractorTests {

    @Rule
    public ExpectedException expectedExcpetion = ExpectedException.none();

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private Settings globalSettings;

    @Before
    public void before() {
        ESLoggerFactory.getLogger("test").setLevel("debug");
        globalSettings = Settings.builder().put("path.home", temporaryFolder.getRoot().getAbsolutePath()).build();
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_principal_is_missing() throws IOException {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_principal");

        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_keytab_path", temporaryFolder.newFile().getAbsolutePath())
                .build();
        new KerberosTokenExtractor(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_path_is_missing() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_keytab_path");

        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_principal", "acceptor_principal")
                .build();
        new KerberosTokenExtractor(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_is_not_readable() throws IOException {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        File keytab = temporaryFolder.newFile();
        assertEquals(true, keytab.setReadable(false));

        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_keytab_path", keytab.getAbsolutePath())
                .put("acceptor_principal", "acceptor_principal")
                .build();
        new KerberosTokenExtractor(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_is_a_directory() throws IOException {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        Settings realmSettings = Settings.builder()
                .put("type", KerberosRealm.TYPE)
                .put("acceptor_keytab_path", temporaryFolder.newFolder().getAbsolutePath())
                .put("acceptor_principal", "")
                .build();
        new KerberosTokenExtractor(new RealmConfig("test", realmSettings, globalSettings));
    }
}
