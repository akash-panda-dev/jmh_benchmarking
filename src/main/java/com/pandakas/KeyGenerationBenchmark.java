package com.pandakas;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;
import org.openjdk.jmh.util.Statistics;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode({Mode.AverageTime, Mode.Throughput, Mode.SampleTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(1)
public class KeyGenerationBenchmark {
    private X509EncodedKeySpec ecKeySpec;
    private X509EncodedKeySpec rsaKeySpec;
    private X509EncodedKeySpec edKeySpec;

    // Different key sizes for RSA
    private X509EncodedKeySpec rsaKeySpec1024;
    private X509EncodedKeySpec rsaKeySpec2048;
    private X509EncodedKeySpec rsaKeySpec4096;

    // Different curves for EC
    private X509EncodedKeySpec ecKeySpecP256;
    private X509EncodedKeySpec ecKeySpecP384;
    private X509EncodedKeySpec ecKeySpecP521;

    @Setup
    public void setup() throws Exception {
        // Initialize BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        setupRSAKeys();
        setupECKeys();
        setupEdDSAKeys();
    }

    private void setupRSAKeys() throws Exception {
        // RSA Keys with different sizes
        rsaKeySpec1024 = generateRSAKeySpec(1024);
        rsaKeySpec2048 = generateRSAKeySpec(2048);
        rsaKeySpec4096 = generateRSAKeySpec(4096);
        rsaKeySpec = rsaKeySpec2048; // Default for compatibility
    }

    private void setupECKeys() throws Exception {
        // EC Keys with different curves
        ecKeySpecP256 = generateECKeySpec("secp256r1");
        ecKeySpecP384 = generateECKeySpec("secp384r1");
        ecKeySpecP521 = generateECKeySpec("secp521r1");
        ecKeySpec = ecKeySpecP256; // Default for compatibility
    }

    private void setupEdDSAKeys() throws Exception {
        try {
            KeyPairGenerator edGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
            KeyPair edPair = edGenerator.generateKeyPair();
            edKeySpec = new X509EncodedKeySpec(edPair.getPublic().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Ed25519 not supported: " + e.getMessage());
        }
    }

    private X509EncodedKeySpec generateRSAKeySpec(int keySize) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(keySize);
        KeyPair pair = generator.generateKeyPair();
        return new X509EncodedKeySpec(pair.getPublic().getEncoded());
    }

    private X509EncodedKeySpec generateECKeySpec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair pair = generator.generateKeyPair();
        return new X509EncodedKeySpec(pair.getPublic().getEncoded());
    }

    // Original benchmarks
    @Benchmark
    public void benchmarkECKey(Blackhole blackhole) throws Exception {
        blackhole.consume(getX509PublicKey(ecKeySpec));
    }

    @Benchmark
    public void benchmarkRSAKey(Blackhole blackhole) throws Exception {
        blackhole.consume(getX509PublicKey(rsaKeySpec));
    }

    @Benchmark
    public void benchmarkEdDSAKey(Blackhole blackhole) throws Exception {
        blackhole.consume(getX509PublicKey(edKeySpec));
    }

    // Main key generation method
    private static PublicKey getX509PublicKey(X509EncodedKeySpec keySpec) 
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        try {
            return (ECPublicKey) KeyFactory.getInstance("EC", "BC").generatePublic(keySpec);
        } catch (InvalidKeySpecException | NoSuchProviderException e) {
            try {
                return (RSAPublicKey) KeyFactory.getInstance("RSA", "BC").generatePublic(keySpec);
            } catch (InvalidKeySpecException | NoSuchProviderException e2) {
                try {
                    return KeyFactory.getInstance("Ed25519", "BC").generatePublic(keySpec);
                } catch (InvalidKeySpecException | NoSuchProviderException e3) {
                    throw e;
                }
            }
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(KeyGenerationBenchmark.class.getSimpleName())
                .timeUnit(TimeUnit.MICROSECONDS)
                .timeout(TimeValue.seconds(10))
                .build();

        new Runner(opt).run();
    }
}
