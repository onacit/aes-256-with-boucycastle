package com.github.onacit;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static java.util.concurrent.ThreadLocalRandom.current;

@Slf4j
public class Main {

//    private static final String ALGORITHM = "AES";

//    private static final String MODE = "CBC";

//    private static final String PADDING = "PKCS5Padding";

//    private static final String TRANSFORMATION = ALGORITHM + '/' + MODE + '/' + PADDING;

    private static final int BLOCK_SIZE = 128;

    private static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE >> 3;

    private static final int KEY_SIZE = 256;

//    private static final int KEY_SIZE_IN_BYTES = KEY_SIZE >> 3;

    static void encrypt(final char[] password, final byte[] salt, final int iterations, final byte[] iv,
                        final Path source, final Path target)
            throws Exception {
        final PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, iterations);
        final CipherParameters derivedMacParameters = generator.generateDerivedMacParameters(KEY_SIZE);
        final PaddedBufferedBlockCipher cipher
                = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        final CipherParameters parametersWithIV = new ParametersWithIV(derivedMacParameters, iv);
        cipher.init(true, parametersWithIV);
        try (InputStream is = new FileInputStream(source.toFile());
             OutputStream os = new FileOutputStream(target.toFile());
             org.bouncycastle.crypto.io.CipherOutputStream cos
                     = new org.bouncycastle.crypto.io.CipherOutputStream(os, cipher)) {
            final byte[] buffer = new byte[current().nextInt(256, 1024)];
            for (int r; (r = is.read(buffer)) != -1; ) {
                cos.write(buffer, 0, r);
            }
            cos.flush();
        }
    }

    static void decrypt(final char[] password, final byte[] salt, final int iterations, final byte[] iv,
                        final Path source, final Path target)
            throws Exception {
        final PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, iterations);
        final CipherParameters derivedMacParameters = generator.generateDerivedMacParameters(KEY_SIZE);
        final PaddedBufferedBlockCipher cipher
                = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        final CipherParameters parametersWithIV = new ParametersWithIV(derivedMacParameters, iv);
        cipher.init(false, parametersWithIV);
        try (InputStream is = new FileInputStream(source.toFile());
             CipherInputStream cis = new CipherInputStream(is, cipher);
             OutputStream os = new FileOutputStream(target.toFile())) {
            final byte[] buffer = new byte[current().nextInt(256, 1024)];
            for (int r; (r = cis.read(buffer)) != -1; ) {
                os.write(buffer, 0, r);
            }
            os.flush();
        }
    }

    public static void main(final String... args) throws Exception {

        final char[] password = "password".toCharArray();

        final byte[] salt = new byte[1024];
        current().nextBytes(salt);

        final int iterations = current().nextInt(65536);

        final byte[] iv = new byte[BLOCK_SIZE_IN_BYTES];
        current().nextBytes(iv);

        {
            final Path plain = Files.createTempFile(null, null);
            {
                final byte[] bytes = new byte[current().nextInt(1048576)];
                current().nextBytes(bytes);
                Files.write(plain, bytes);
            }
            final Path encrypted = Files.createTempFile(null, null);
            encrypt(password, salt, iterations, iv, plain, encrypted);
            final Path decrypted = Files.createTempFile(null, null);
            decrypt(password, salt, iterations, iv, encrypted, decrypted);
            assert Arrays.equals(Files.readAllBytes(plain), Files.readAllBytes(decrypted));
        }
    }
}
