package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

public class LivenessToken extends KerberosToken {
    public static final LivenessToken INSTANCE = new LivenessToken();

    private LivenessToken() {
        super(new byte[0]);
    }

    @Override
    public void clearCredentials() {
    }
}
