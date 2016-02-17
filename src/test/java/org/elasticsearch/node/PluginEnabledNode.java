package org.elasticsearch.node;

import java.util.Collection;

import org.elasticsearch.Version;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.node.Node;
import org.elasticsearch.plugins.Plugin;

public class PluginEnabledNode extends Node{

    public PluginEnabledNode(Settings preparedSettings, Collection<Class<? extends Plugin>> classpathPlugins) {
        super(preparedSettings);
    }

    
    
}
