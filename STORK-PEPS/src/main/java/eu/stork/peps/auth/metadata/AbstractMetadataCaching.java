package eu.stork.peps.auth.metadata;

import eu.stork.peps.auth.engine.metadata.MetadataGenerator;
import org.opensaml.saml2.metadata.EntityDescriptor;

import java.util.Map;

public abstract class AbstractMetadataCaching implements IMetadataCachingService {
    private MetadataGenerator generator;

    public AbstractMetadataCaching(){
        init();
    }
    private void init(){
        generator = new MetadataGenerator();
    }
    @Override
    public final EntityDescriptor getDescriptor(String url) {
        if(getMap()!=null){
            SerializedEntityDescriptor content=getMap().get(url);
            if(content!=null && !content.getSerializedEntityDescriptor().isEmpty()) {
                return deserialize(content.getSerializedEntityDescriptor());
            }
        }
        return null;
    }

    @Override
    public final void putDescriptor(String url, EntityDescriptor ed, EntityDescriptorType type) {
        if(getMap()!=null){
            if(ed==null){
                getMap().remove(url);
            }else {
                String content = serialize(ed);
                if (content != null && !content.isEmpty()) {
                    getMap().put(url, new SerializedEntityDescriptor(content, type));
                }
            }
        }
    }
    @Override
    public final EntityDescriptorType getDescriptorType(String url) {
        if (getMap() != null) {
            SerializedEntityDescriptor content = getMap().get(url);
            if (content != null) {
                return content.getType();
            }
        }
        return null;
    }

    private String serialize(EntityDescriptor ed){
        return generator.serializeEntityDescriptor(ed);
    }

    private EntityDescriptor deserialize(String content){
        return generator.deserializeEntityDescriptor(content);
    }

    protected abstract Map<String, SerializedEntityDescriptor> getMap();

}
