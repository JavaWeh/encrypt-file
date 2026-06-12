package com.lczy.encryptfile.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 最小化编译检查的使用示例，供依赖此工具包的应用参考。
 * 该方法故意不使用 JUnit 测试；README 中的代码片段可与此类保持一致。
 *
 * 本类演示了 LczyResourceService 的三种典型使用场景：
 * 1. 加密 ZIP 并从中读取单个文件
 * 2. 直接构建资源列表并加密（无需预先创建 ZIP）
 * 3. 流式处理方式（适用于大文件）
 *
 * @author JavaWeh
 */
class LczyUsageExample {

    /**
     * 场景1：加密 ZIP 字节数组，然后从加密后的数据中读取指定文件
     *
     * @param zipBytes 原始 ZIP 文件的字节数组
     * @return 从加密包中读取出的 "docs/readme.txt" 文件内容
     */
    byte[] encryptAndReadOneFile(byte[] zipBytes) {
        // 将 AES 密钥（32字节，对应 AES-256）编码为 Base64 字符串
        // 注意：实际使用时密钥应安全存储，此处仅为示例
        String keyBase64 = Base64.getEncoder()
                .encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));

        // 创建基于 Base64 编码密钥的密钥提供者，并构建服务实例
        LczyResourceService service = new LczyResourceService(new Base64AesKeyProvider(keyBase64));

        // 加密 ZIP 文件，返回加密后的数据包
        byte[] lczyBytes = service.encryptZip(zipBytes);

        // 从加密包中读取指定路径的文件内容
        return service.readFile(lczyBytes, "docs/readme.txt");
    }

    /**
     * 场景2：无需预先创建 ZIP，直接构建资源列表并加密
     *
     * @return 加密后的数据包字节数组
     */
    byte[] buildWithoutZip() {
        // 使用 Lambda 表达式实现密钥提供者接口
        // 直接返回 SecretKeySpec 对象（AES 算法，32字节密钥）
        ResourceKeyProvider keyProvider = () -> new SecretKeySpec(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8),
                "AES"
        );

        LczyResourceService service = new LczyResourceService(keyProvider);

        // 构建资源列表：包含两个文件条目
        // - docs/readme.txt：文本文件，内容为 "hello"
        // - assets/config.json：JSON 配置文件，内容为 {"enabled":true}
        return service.encryptResources(List.of(
                new ZipEntryResource("docs/readme.txt", "hello".getBytes(StandardCharsets.UTF_8)),
                new ZipEntryResource("assets/config.json", "{\"enabled\":true}".getBytes(StandardCharsets.UTF_8))
        ));
    }

    /**
     * 场景3：流式处理方式，适用于大文件场景，避免一次性加载全部数据到内存
     *
     * @param zipBytes 原始 ZIP 文件的字节数组
     * @return 加密后的数据包字节数组
     */
    byte[] streamStyle(byte[] zipBytes) {
        // 使用方法引用，从数据库/KMS 中加载密钥
        LczyResourceService service = new LczyResourceService(this::loadKeyFromDatabase);

        // 创建输出流，用于接收加密结果
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        // 将输入流（ZIP 数据）加密后写入输出流（流式处理，内存友好）
        service.encryptZip(new ByteArrayInputStream(zipBytes), output);

        return output.toByteArray();
    }

    /**
     * 从数据库或 KMS（密钥管理服务）加载 AES 密钥的示例方法
     *
     * 实际项目中应替换为：
     * - 数据库查询（如通过 Mapper/Repository）
     * - 配置中心调用
     * - KMS/HSM 硬件安全模块获取
     * - 环境变量/密钥文件读取（需配合访问控制）
     *
     * @return AES 密钥对象（此处使用固定密钥仅作演示）
     */
    private SecretKey loadKeyFromDatabase() {
        // 实际生产环境中请替换为真实的密钥获取逻辑
        // 例如：return keyMapper.findByAlias("default_aes_key");
        // 或者：return kmsClient.decrypt(encryptedKey);
        byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(key, "AES");
    }
}