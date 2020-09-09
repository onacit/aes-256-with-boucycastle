package com.github.onacit;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Arrays;

import static java.util.concurrent.ThreadLocalRandom.current;

@Slf4j
public class Main {

    private static final String ALGORITHM = "AES";

    private static final String MODE = "CBC";

    private static final String PADDING = "PKCS5Padding";

    private static final String TRANSFORMATION = ALGORITHM + '/' + MODE + '/' + PADDING;

    private static final int KEY_LENGTH_IN_BYTES = 32;

    private static final int KEY_LENGTH_IN_BITS = KEY_LENGTH_IN_BYTES << 3;

    public static void main(final String... args) throws Exception {

        final char[] password = "password".toCharArray();
        final byte[] salt = new byte[1024];
        current().nextBytes(salt);
        final int iteration = 65536;

        final byte[] ivBytes = new byte[16]; // 128, regardless of key size
        current().nextBytes(ivBytes);

        final byte[] keyBytes = new byte[KEY_LENGTH_IN_BYTES]; // 256
        current().nextBytes(keyBytes);

        final byte[] plain = new byte[1048576];
        current().nextBytes(plain);

        final byte[] bcEncrypted;
        final byte[] bcDecrypted;

        final byte[] jceEncrypted;
        final byte[] jceDecrypted;

        {
            final PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
            generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, iteration);
            final CipherParameters derivedMacParameters = generator.generateDerivedMacParameters(KEY_LENGTH_IN_BITS);
            final PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            final CipherParameters parametersWithIV = new ParametersWithIV(derivedMacParameters, ivBytes);
            cipher.init(true, parametersWithIV);
            final byte[] encrypted = new byte[cipher.getOutputSize(plain.length)];
            int encLen = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
            encLen += cipher.doFinal(encrypted, encLen);
            bcEncrypted = Arrays.copyOf(encrypted, encLen);
            cipher.init(false, parametersWithIV);
            final byte[] decrypted = new byte[cipher.getOutputSize(encLen)];
            int decLen = cipher.processBytes(encrypted, 0, encLen, decrypted, 0);
            decLen += cipher.doFinal(decrypted, decLen);
            bcDecrypted = Arrays.copyOf(decrypted, decLen);
            assert Arrays.equals(plain, bcDecrypted);
        }

        {
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            final KeySpec keySpec = new PBEKeySpec(password, salt, iteration, KEY_LENGTH_IN_BITS);
            final Key key = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), ALGORITHM);
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            final AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameterSpec);
            jceEncrypted = cipher.doFinal(plain);
            cipher.init(Cipher.DECRYPT_MODE, key, algorithmParameterSpec);
            jceDecrypted = cipher.doFinal(jceEncrypted);
            assert Arrays.equals(plain, jceDecrypted);
        }

        assert Arrays.equals(bcEncrypted, jceEncrypted);
        assert Arrays.equals(bcDecrypted, jceDecrypted);
    }
}
