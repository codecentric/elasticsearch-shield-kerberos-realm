package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.RolesProvider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.test.ESTestCase;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.nio.file.Path;

public class RolesProviderTests extends ESTestCase {

    private Settings globalSettings;

    @Before
    public void before() {
        Path tempDirPath = createTempDir("tempdir-unittest");
        globalSettings = Settings.builder().put("path.home", tempDirPath).build();
    }

    @Test
    public void should_return_the_roles_of_a_user() {
        Settings realmSettings = Settings.builder()
                .put("roles.role1.0", "user")
                .put("roles.role2.1", "someone")
                .put("roles.role2.0", "user")
                .build();
        RealmConfig config = new RealmConfig("test", realmSettings, globalSettings);

        Assert.assertArrayEquals(new String[]{"role1", "role2"}, new RolesProvider(config).getRoles("user"));
    }

    @Test
    public void should_return_no_roles_when_no_roles_are_configured() {
        RealmConfig config = new RealmConfig("test", Settings.EMPTY, globalSettings);

        Assert.assertArrayEquals(new String[0], new RolesProvider(config).getRoles("user"));
    }

    @Test
    public void should_return_no_roles_when_the_username_is_null() {
        RealmConfig config = new RealmConfig("test", Settings.EMPTY, globalSettings);

        Assert.assertArrayEquals(new String[0], new RolesProvider(config).getRoles(null));
    }
}
