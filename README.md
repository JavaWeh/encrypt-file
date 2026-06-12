# encrypt-file

[![Java](https://img.shields.io/badge/Java-17%2B-blue)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.x-brightgreen)](https://spring.io/projects/spring-boot)

`encrypt-file` 是一个 LCZY 资源包加解密工具包，用于把 ZIP 资源包转换为自定义 `.lczy`
二进制格式，并支持按 manifest 随机定位、解密单个资源文件。

项目地址：[github.com/JavaWeh/encrypt-file](https://github.com/JavaWeh/encrypt-file)

## 特性

- AES-256-GCM 加密，每个文件块使用独立 IV 和认证标签。
- 文件块边读边压缩、边加密、边写出，降低大资源包处理时的峰值内存。
- manifest 记录路径、偏移、密文大小、原始大小、SHA-256 摘要和文件块 IV。
- 索引区加密，资源路径、偏移量、摘要等信息不会暴露在外层明文 metadata 中。
- LCZY v2 使用尾部索引，读取端可以只读取 footer、索引区和目标文件块。
- 支持 `SeekableByteChannel` 和对象存储 Range GET 随机读取。
- metadata 记录 `keyId`，`ResourceKeyProvider` 可按 `keyId` 获取历史密钥，便于密钥轮换。
- 核心能力不依赖 `spring-boot-starter`，Spring Boot 自动配置作为可选接入方式提供。
- `LczyFormatReader` SPI 按版本分发解析逻辑，便于未来格式升级并兼容旧包。

## 环境要求

- JDK 17+
- Maven 3.8+

## 安装

当前版本：`0.0.2`

### 从 GitHub Packages 引入

GitHub Packages Maven Registry 需要先在消费方项目中声明仓库：

```xml
<repositories>
    <repository>
        <id>github</id>
        <name>GitHub Packages</name>
        <url>https://maven.pkg.github.com/javaweh/encrypt-file</url>
    </repository>
</repositories>
```

然后引入依赖：

```xml
<dependency>
    <groupId>com.ljzy</groupId>
    <artifactId>encrypt-file</artifactId>
    <version>0.0.2</version>
</dependency>
```

GitHub Packages 不是 Maven Central。其他项目下载依赖时，需要在 Maven `settings.xml` 中配置
拥有 `read:packages` 权限的 GitHub Token：

```xml
<settings>
    <servers>
        <server>
            <id>github</id>
            <username>YOUR_GITHUB_USERNAME</username>
            <password>YOUR_GITHUB_TOKEN</password>
        </server>
    </servers>
</settings>
```

### 本地安装

本地构建并安装到 Maven 本地仓库：

```bash
./mvnw clean install
```

Windows PowerShell：

```powershell
.\mvnw.cmd clean install
```

如果希望把依赖下载到项目内 `.m2repo`，可以执行：

```bash
./mvnw -Dmaven.repo.local=.m2repo clean install
```

### 发布到 GitHub Packages

项目已配置 GitHub Actions：发布 GitHub Release，或在 Actions 页面手动运行
`Publish Maven Package` 工作流，会执行：

```bash
./mvnw -B -ntp deploy
```

工作流使用仓库内置的 `GITHUB_TOKEN` 发布到：

```text
https://maven.pkg.github.com/javaweh/encrypt-file
```

发布新版本前，请先修改 `pom.xml` 中的 `<version>`，并确保 GitHub 仓库的
Actions 权限允许写入 Packages。

## 快速开始

### 准备密钥

密钥必须是 32 字节 AES key。示例：

```java
byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
String keyBase64 = Base64.getEncoder().encodeToString(key);
```

生产环境不要把真实密钥写在代码或配置仓库中，建议从环境变量、KMS、Vault、数据库密钥表或配置中心读取。

### 加密 ZIP、读取单文件、还原 ZIP

```java
import com.lczy.encryptfile.crypto.Base64AesKeyProvider;
import com.lczy.encryptfile.crypto.LczyResourceService;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
String keyBase64 = Base64.getEncoder().encodeToString(key);

LczyResourceService service = new LczyResourceService(
        new Base64AesKeyProvider(keyBase64, "key-2026-06")
);

byte[] lczyBytes = service.encryptZip(zipBytes);
byte[] readmeBytes = service.readFile(lczyBytes, "docs/readme.txt");
byte[] zipBytesAgain = service.decryptToZip(lczyBytes);
```

### 不经过 ZIP，直接构建资源包

```java
import com.lczy.encryptfile.crypto.LczyResourceService;
import com.lczy.encryptfile.crypto.ZipEntryResource;

import java.nio.charset.StandardCharsets;
import java.util.List;

byte[] lczyBytes = service.encryptResources(List.of(
        new ZipEntryResource("docs/readme.txt", "hello".getBytes(StandardCharsets.UTF_8)),
        new ZipEntryResource("assets/config.json", "{\"enabled\":true}".getBytes(StandardCharsets.UTF_8))
));
```

### 流式写出 LCZY

```java
try (InputStream zipInput = Files.newInputStream(Path.of("assets.zip"));
     OutputStream lczyOutput = Files.newOutputStream(Path.of("assets.lczy"))) {
    service.encryptZip(zipInput, lczyOutput);
}
```

### 随机读取本地文件

```java
import com.lczy.encryptfile.crypto.LczyReader;

import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

try (SeekableByteChannel channel = Files.newByteChannel(Path.of("assets.lczy"), StandardOpenOption.READ)) {
    LczyReader reader = new LczyReader(channel, keyProvider);
    byte[] config = reader.readFile("assets/config.json");
}
```

### 对象存储 Range GET 读取

业务系统只需要实现 `LczyRangeSource`：

```java
import com.lczy.encryptfile.crypto.LczyRangeSource;

public class OssRangeSource implements LczyRangeSource {

    private final String bucket;
    private final String objectKey;
    private final long size;

    public OssRangeSource(String bucket, String objectKey, long size) {
        this.bucket = bucket;
        this.objectKey = objectKey;
        this.size = size;
    }

    @Override
    public long size() {
        return size;
    }

    @Override
    public byte[] read(long position, int length) {
        return ossClient.getRange(bucket, objectKey, position, position + length - 1);
    }
}
```

然后：

```java
LczyReader reader = new LczyReader(new OssRangeSource(bucket, objectKey, objectSize), keyProvider);
byte[] file = reader.readFile("docs/readme.txt");
```

## Spring Boot 接入

引入依赖后，可以通过配置文件提供密钥：

```yaml
lczy:
  crypto:
    key-base64: ${LCZY_CRYPTO_KEY_BASE64}
    key-id: ${LCZY_CRYPTO_KEY_ID:key-2026-06}
```

业务代码直接注入：

```java
import com.lczy.encryptfile.crypto.LczyResourceService;
import org.springframework.stereotype.Service;

@Service
public class ResourcePackageAppService {

    private final LczyResourceService lczyResourceService;

    public ResourcePackageAppService(LczyResourceService lczyResourceService) {
        this.lczyResourceService = lczyResourceService;
    }

    public byte[] encryptZip(byte[] zipBytes) {
        return lczyResourceService.encryptZip(zipBytes);
    }

    public byte[] readOneFile(byte[] lczyBytes, String path) {
        return lczyResourceService.readFile(lczyBytes, path);
    }
}
```

生产项目推荐自定义 `ResourceKeyProvider`，按 `keyId` 支持历史密钥：

```java
import com.lczy.encryptfile.crypto.LczyException;
import com.lczy.encryptfile.crypto.ResourceKeyProvider;

import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LczyKeyConfiguration {

    @Bean
    public ResourceKeyProvider resourceKeyProvider(CryptoKeyRepository repository) {
        return new ResourceKeyProvider() {
            @Override
            public SecretKey getKey() {
                return getKey(currentKeyId());
            }

            @Override
            public String currentKeyId() {
                return repository.findCurrentKeyId("LCZY_AES_256_GCM");
            }

            @Override
            public SecretKey getKey(String keyId) {
                String base64Key = repository.findKeyById(keyId)
                        .orElseThrow(() -> new LczyException("LCZY key not found: " + keyId));
                byte[] keyBytes = Base64.getDecoder().decode(base64Key);
                return new SecretKeySpec(keyBytes, "AES");
            }
        };
    }
}
```

项目中存在自定义 `ResourceKeyProvider` Bean 时，自动配置会优先使用该 Bean。

## LCZY v2 格式

### 外层容器

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| magic | 4 bytes | 固定魔数 `LCZY` |
| version | 1 byte | 当前新包为 `2` |
| alg | 1 byte | 算法标识，当前为 AES-256-GCM |
| ivLength | 1 byte | 索引区 IV 长度 |
| iv | 12 bytes | 索引区 AES-GCM IV |
| metaLength | 4 bytes | 外层 metadata JSON 长度 |
| metaJson | N bytes | 外层 metadata，包含 version、algorithm、keyId 等最小信息 |
| encryptedFileBlocks | N bytes | 多个文件密文块连续写入 |
| encryptedIndex | N bytes | 加密 manifest |
| footer | 固定长度 | 记录 encryptedIndex 的 offset、length 和 footer magic |

### 文件块处理流程

```text
原始文件 bytes
  -> 同步计算 SHA-256
  -> Deflate 压缩
  -> AES-256-GCM 加密
  -> 写入 LCZY 文件数据区
```

### manifest 关键字段

| 字段 | 说明 |
| --- | --- |
| path | 归一化后的资源路径 |
| offset | 相对文件数据区起点的偏移量 |
| encryptedSize | 单个文件密文块长度，包含 GCM tag |
| compressedSize | 压缩后、加密前长度 |
| originalSize | 原始文件长度 |
| sha256 | 原始文件 bytes 的 SHA-256 hex 摘要 |
| iv | 单文件 AES-GCM IV |

读取时先由 AES-GCM 校验密文完整性，再对解压后的原始文件重新计算 SHA-256，与 manifest 中的
`sha256` 比对，便于审计和排查传输损坏。

## 多版本兼容

`LczyResourceService` 只识别 `LCZY` 魔数和 version，然后分发给对应的 `LczyFormatReader`：

- `LczyV1FormatReader`：兼容旧 v1 包。
- `LczyV2FormatReader`：读取当前尾部索引 v2 包。
- 自定义 reader：通过构造函数传入，或使用 Java `ServiceLoader<LczyFormatReader>` 注册。

自定义版本读取器示意：

```java
public final class LczyV3FormatReader implements LczyFormatReader {
    @Override
    public int version() {
        return 3;
    }

    // 实现 readMetadata/readManifest/readFile/decryptPackage
}
```

如需通过 `ServiceLoader` 自动加载，在依赖 JAR 中增加：

```text
META-INF/services/com.lczy.encryptfile.crypto.LczyFormatReader
```

文件内容写入实现类全限定名：

```text
com.example.crypto.LczyV3FormatReader
```

## 常用 API

| 方法或类型 | 说明 |
| --- | --- |
| `LczyResourceService.encryptZip(byte[])` | ZIP bytes 转 LCZY bytes |
| `LczyResourceService.encryptZip(InputStream)` | ZIP 输入流转 LCZY bytes |
| `LczyResourceService.encryptZip(InputStream, OutputStream)` | ZIP 输入流转 LCZY 输出流 |
| `LczyResourceService.encryptResources(List<ZipEntryResource>)` | 不经过 ZIP，直接从内存资源构建 LCZY |
| `LczyResourceService.readManifest(byte[])` | 解密并读取 manifest，不解密所有文件块 |
| `LczyResourceService.readFile(byte[], String)` | 从内存 LCZY 包读取单个文件 |
| `LczyResourceService.decryptPackage(byte[])` | 解密所有文件为内存 Map |
| `LczyResourceService.decryptToZip(byte[])` | LCZY 解密回 ZIP bytes |
| `LczyWriter` | 流式写 LCZY，适合大 ZIP 输入 |
| `LczyReader` | 基于 `SeekableByteChannel` 或 `LczyRangeSource` 随机读取 |
| `ResourceKeyProvider` | 当前密钥与历史密钥提供器 |
| `LczyFormatReader` | 多版本格式解析 SPI |

## 安全建议

- 不要把真实密钥提交到 Git。
- AES-256-GCM 密钥必须是 32 bytes。
- `keyId` 应和密钥表、KMS key version 或配置中心版本对应。
- 轮换密钥时，新包使用新 `keyId` 加密，旧包通过 metadata 中的 `keyId` 找历史密钥解密。
- IV 由工具内部 `SecureRandom` 自动生成，业务方不需要传入。
- 外层 metadata 是明文，敏感业务元数据应放在加密 manifest 中。
- 单个文件读取会校验 AES-GCM tag 和 SHA-256 摘要；校验失败会抛出 `LczyException`。

## 构建与测试

```bash
./mvnw test
```

Windows PowerShell：

```powershell
.\mvnw.cmd test
```

更多可编译示例见：

```text
src/test/java/com/lczy/encryptfile/crypto/LczyUsageExample.java
```

## 作者

JavaWeh

## License

This project is licensed under the [Apache License 2.0](LICENSE).
