package com.lczy.encryptfile.crypto;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for LCZY crypto services.
 *
 * <p>Applications can override either bean by declaring their own
 * {@link ResourceKeyProvider} or {@link LczyResourceService}.</p>
 *
 * @author JavaWeh
 */
@AutoConfiguration
@EnableConfigurationProperties(LczyCryptoProperties.class)
public class LczyCryptoAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ResourceKeyProvider resourceKeyProvider(LczyCryptoProperties properties) {
        return new Base64AesKeyProvider(properties.getKeyBase64(), properties.getKeyId());
    }

    @Bean
    @ConditionalOnMissingBean
    public LczyResourceService lczyResourceService(ResourceKeyProvider keyProvider) {
        return new LczyResourceService(keyProvider);
    }
}
