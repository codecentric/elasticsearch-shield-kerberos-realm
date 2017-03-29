package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RolesProvider {
    private final HashMap<String, List<String>> rolesMap = new HashMap<>();
    private static final String ROLES = "roles";

    public RolesProvider(RealmConfig config) {
        ESLogger logger = config.logger(RolesProvider.class);
        Map<String, Settings> roleGroups = config.settings().getGroups(ROLES + ".");

        for (String role : roleGroups.keySet()) {
            for (String principal : config.settings().getAsArray(ROLES + "." + role)) {
                if (!rolesMap.containsKey(principal)) {
                    rolesMap.put(principal, new ArrayList<String>());
                }
                rolesMap.get(principal).add(role);
            }
        }

        logger.debug("Parsed roles: {}", rolesMap);
    }

    public String[] getRoles(String principal) {
        return rolesMap.containsKey(principal) ? rolesMap.get(principal).toArray(new String[0]) : new String[0];
    }
}
