package de.codecentric.elasticsearch.plugin.kerberosrealm.utils;

import org.elasticsearch.common.SuppressForbidden;
import org.junit.rules.ExternalResource;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

@SuppressForbidden(reason = "platform independent")
public class TemporaryFilesRule  extends ExternalResource {
    private Path tempDirectory;

    @Override
    protected void before() throws IOException {
        this.tempDirectory = Files.createTempDirectory(Paths.get(""), "kerberos-realm");
    }

    public Path getRoot() {
        return tempDirectory;
    }

    private void delete() throws IOException {
        Files.walkFileTree(tempDirectory, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    @Override
    protected void after() {
//        try {
//            this.delete();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }
}
