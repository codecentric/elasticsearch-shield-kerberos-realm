package de.codecentric.elasticsearch.plugin.kerberosrealm;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class KerberosRealmIT {

    @Test
    public void should_initially_responds_with_status_code_401() throws IOException {
        String url = System.getProperty("elasticsearch.url");

        HttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet(url);
        HttpResponse response = client.execute(request);

        Assert.assertEquals(response.getStatusLine().getStatusCode(), 401);
    }
}