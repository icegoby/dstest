package main

import (
    "fmt"
    "math/big"
    "testing"
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/elliptic"
    "crypto/ecdsa"
)

const MSG_LEN = 1500

type ellipticCurve int

const (
    P224 ellipticCurve = iota
    P256
    P384
    P521
)

func main() {
    plain := make([]byte, MSG_LEN)
    n, err := rand.Read(plain)
    if err != nil {
        panic(err)
    }
    if n != MSG_LEN {
        panic("plain length mismatch")
    }

    sign, verify := RSAtest(plain, 2048)
    fmt.Printf("RSA 2048,%d,%d\n", sign, verify)
    sign, verify = RSAtest(plain, 4096)
    fmt.Printf("RSA 4096,%d,%d\n", sign, verify)

    sign, verify = DSAtest(plain, dsa.L1024N160)
    fmt.Printf("DSA L1024N160,%d,%d\n", sign, verify)
    sign, verify = DSAtest(plain, dsa.L2048N224)
    fmt.Printf("DSA L2048N224,%d,%d\n", sign, verify)
    sign, verify = DSAtest(plain, dsa.L2048N256)
    fmt.Printf("DSA L2048N256,%d,%d\n", sign, verify)
    sign, verify = DSAtest(plain, dsa.L3072N256)
    fmt.Printf("DSA L3072N256,%d,%d\n", sign, verify)

    sign, verify = ECDSAtest(plain, P224)
    fmt.Printf("ECDSA P224,%d,%d\n", sign, verify)
    sign, verify = ECDSAtest(plain, P256)
    fmt.Printf("ECDSA P256,%d,%d\n", sign, verify)
    sign, verify = ECDSAtest(plain, P384)
    fmt.Printf("ECDSA P384,%d,%d\n", sign, verify)
    sign, verify = ECDSAtest(plain, P521)
    fmt.Printf("ECDSA P521,%d,%d\n", sign, verify)
}

func RSAtest(plain []byte, keyLen int) (int64, int64) {
    priv, err := rsa.GenerateKey(rand.Reader, keyLen)
    if err != nil {
        panic(err)
    }
    result := testing.Benchmark(func(b *testing.B){ RSAsign(b, priv, plain) })
    sign := result.T.Nanoseconds() / int64(result.N)

    hashed := sha256.Sum256(plain)
    signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
    if err != nil {
        panic(err)
    }

    result = testing.Benchmark(func(b *testing.B){ RSAverify(b, priv, plain, signature) })
    return sign, result.T.Nanoseconds() / int64(result.N)
}

func DSAtest(plain []byte, sz dsa.ParameterSizes) (int64, int64) {
    var dsaPriv dsa.PrivateKey

    err := dsa.GenerateParameters(&dsaPriv.PublicKey.Parameters, rand.Reader, sz)
    if err != nil {
        panic(err)
    }
    err = dsa.GenerateKey(&dsaPriv, rand.Reader)
    if err != nil {
        panic(err)
    }
    result := testing.Benchmark(func(b *testing.B){ DSAsign(b, &dsaPriv, plain) })
    sign := result.T.Nanoseconds() / int64(result.N)

    hashed := sha256.Sum256(plain)
    r, s, err := dsa.Sign(rand.Reader, &dsaPriv, hashed[:])
    if err != nil {
        panic(err)
    }
    result = testing.Benchmark(func(b *testing.B){ DSAverify(b, &dsaPriv, plain, r, s) })
    return sign, result.T.Nanoseconds() / int64(result.N)
}

func ECDSAtest(plain []byte, p ellipticCurve) (int64, int64) {
    pFunc := [](func() elliptic.Curve){elliptic.P224, elliptic.P256, elliptic.P384, elliptic.P521}

    priv, err := ecdsa.GenerateKey(pFunc[p](), rand.Reader)
    if err != nil {
        panic(err)
    }
    result := testing.Benchmark(func(b *testing.B){ ECDSAsign(b, priv, plain) })
    sign := result.T.Nanoseconds() / int64(result.N)

    hashed := sha256.Sum256(plain)
    r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
    if err != nil {
        panic(err)
    }

    result = testing.Benchmark(func(b *testing.B){ ECDSAverify(b, priv, plain, r, s) })
    return sign, result.T.Nanoseconds() / int64(result.N)
}

func RSAsign(b *testing.B, priv *rsa.PrivateKey, plain []byte) {
    for i := 0; i < b.N; i++ {
        hashed := sha256.Sum256(plain)
        signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
        if err != nil {
            panic(err)
        }
        _ = signature
    }
}

func RSAverify(b *testing.B, priv *rsa.PrivateKey, plain []byte, signature []byte) {
    for i := 0; i < b.N; i++ {
        hashed := sha256.Sum256(plain)
        err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], signature)
        if err != nil {
            panic(err)
        }
    }
}

func DSAsign(b *testing.B, priv *dsa.PrivateKey, plain []byte) {
    for i := 0; i < b.N; i++ {
        hashed := sha256.Sum256(plain)
        r, s, err := dsa.Sign(rand.Reader, priv, hashed[:])
        if err != nil {
            panic(err)
        }
        _ = s
        _ = r
    }
}

func DSAverify(b *testing.B, priv *dsa.PrivateKey, plain []byte, r *big.Int, s *big.Int) {
    for i := 0; i < b.N; i++ {
        hashed := sha256.Sum256(plain)
        t := dsa.Verify(&priv.PublicKey, hashed[:], r, s)
        if t != true {
            panic("DSA verify failure")
        }
    }
}

func ECDSAsign(b *testing.B, priv *ecdsa.PrivateKey, plain []byte) {
    for i := 0; i < b.N; i++ {
        hashed := sha256.Sum256(plain)
        r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
        if err != nil {
            panic(err)
        }
        _ = s
        _ = r
    }
}

func ECDSAverify(b *testing.B, priv *ecdsa.PrivateKey, plain []byte, r *big.Int, s *big.Int) {
    for i := 0; i < b.N; i++ {
        hashed := sha256.Sum256(plain)
        t := ecdsa.Verify(&priv.PublicKey, hashed[:], r, s)
        if t != true {
            panic("ECDSA verify failure")
        }
    }
}
