package com.tngtech.elasticsearch.plugin.kerberosrealm;

import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.RolesProvider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.shield.authc.RealmConfig;
import org.junit.Assert;
import org.junit.Test;

import static org.mockito.Mockito.mock;

public class RolesProviderTests {

    @Test
    public void should_return_the_roles_of_a_user() {
        Settings realmSettings = Settings.builder()
                .put("roles.role1.0", "user")
                .put("roles.role2.1", "someone")
                .put("roles.role2.0", "user")
                .build();
        RealmConfig config = new RealmConfig("test", realmSettings, Settings.EMPTY, mock(Environment.class));

        Assert.assertArrayEquals(new String[]{"role1", "role2"}, new RolesProvider(config).getRoles("user"));
    }

    @Test
    public void should_return_no_roles_when_no_roles_are_configured() {
        RealmConfig config = new RealmConfig("test", Settings.EMPTY, Settings.EMPTY, mock(Environment.class));

        Assert.assertArrayEquals(new String[0], new RolesProvider(config).getRoles("user"));
    }

    @Test
    public void should_return_no_roles_when_the_username_is_null() {
        RealmConfig config = new RealmConfig("test", Settings.EMPTY, Settings.EMPTY, mock(Environment.class));

        Assert.assertArrayEquals(new String[0], new RolesProvider(config).getRoles(null));
    }
}
