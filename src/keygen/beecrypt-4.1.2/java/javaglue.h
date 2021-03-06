/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class javax_crypto_Cipher */

#ifndef _Included_javax_crypto_Cipher
#define _Included_javax_crypto_Cipher
#ifdef __cplusplus
extern "C" {
#endif
#undef javax_crypto_Cipher_UNINITIALIZED
#define javax_crypto_Cipher_UNINITIALIZED 0L
#undef javax_crypto_Cipher_ENCRYPT_MODE
#define javax_crypto_Cipher_ENCRYPT_MODE 1L
#undef javax_crypto_Cipher_DECRYPT_MODE
#define javax_crypto_Cipher_DECRYPT_MODE 2L
#undef javax_crypto_Cipher_WRAP_MODE
#define javax_crypto_Cipher_WRAP_MODE 3L
#undef javax_crypto_Cipher_UNWRAP_MODE
#define javax_crypto_Cipher_UNWRAP_MODE 4L
#undef javax_crypto_Cipher_PUBLIC_KEY
#define javax_crypto_Cipher_PUBLIC_KEY 1L
#undef javax_crypto_Cipher_PRIVATE_KEY
#define javax_crypto_Cipher_PRIVATE_KEY 2L
#undef javax_crypto_Cipher_SECRET_KEY
#define javax_crypto_Cipher_SECRET_KEY 3L
#ifdef __cplusplus
}
#endif
#endif
/* Header for class beecrypt_security_NativeMessageDigest */

#ifndef _Included_beecrypt_security_NativeMessageDigest
#define _Included_beecrypt_security_NativeMessageDigest
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    find
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_security_NativeMessageDigest_find
  (JNIEnv *, jclass, jstring);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    allocParam
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_security_NativeMessageDigest_allocParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    cloneParam
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_security_NativeMessageDigest_cloneParam
  (JNIEnv *, jclass, jlong, jlong);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    freeParam
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeMessageDigest_freeParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    reset
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeMessageDigest_reset
  (JNIEnv *, jclass, jlong, jlong);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    update
 * Signature: (JJB)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeMessageDigest_update
  (JNIEnv *, jclass, jlong, jlong, jbyte);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    updateBlock
 * Signature: (JJ[BII)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeMessageDigest_updateBlock
  (JNIEnv *, jclass, jlong, jlong, jbyteArray, jint, jint);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    digest
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_beecrypt_security_NativeMessageDigest_digest
  (JNIEnv *, jclass, jlong, jlong);

/*
 * Class:     beecrypt_security_NativeMessageDigest
 * Method:    digestLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_beecrypt_security_NativeMessageDigest_digestLength
  (JNIEnv *, jclass, jlong);

#ifdef __cplusplus
}
#endif
#endif
/* Header for class beecrypt_security_NativeSecureRandom */

#ifndef _Included_beecrypt_security_NativeSecureRandom
#define _Included_beecrypt_security_NativeSecureRandom
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    find
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_security_NativeSecureRandom_find
  (JNIEnv *, jclass, jstring);

/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    allocParam
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_security_NativeSecureRandom_allocParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    cloneParam
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_security_NativeSecureRandom_cloneParam
  (JNIEnv *, jclass, jlong, jlong);

/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    freeParam
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeSecureRandom_freeParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    setup
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeSecureRandom_setup
  (JNIEnv *, jclass, jlong, jlong);

/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    setSeed
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeSecureRandom_setSeed
  (JNIEnv *, jclass, jlong, jlong, jbyteArray);

/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    nextBytes
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeSecureRandom_nextBytes
  (JNIEnv *, jclass, jlong, jlong, jbyteArray);

/*
 * Class:     beecrypt_security_NativeSecureRandom
 * Method:    generateSeed
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_beecrypt_security_NativeSecureRandom_generateSeed
  (JNIEnv *, jclass, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
/* Header for class beecrypt_crypto_NativeBlockCipher */

#ifndef _Included_beecrypt_crypto_NativeBlockCipher
#define _Included_beecrypt_crypto_NativeBlockCipher
#ifdef __cplusplus
extern "C" {
#endif
#undef beecrypt_crypto_NativeBlockCipher_MODE_ECB
#define beecrypt_crypto_NativeBlockCipher_MODE_ECB 0L
#undef beecrypt_crypto_NativeBlockCipher_MODE_CBC
#define beecrypt_crypto_NativeBlockCipher_MODE_CBC 1L
/* Inaccessible static: MODES */
#undef beecrypt_crypto_NativeBlockCipher_PADDING_NOPADDING
#define beecrypt_crypto_NativeBlockCipher_PADDING_NOPADDING 0L
#undef beecrypt_crypto_NativeBlockCipher_PADDING_PKCS5
#define beecrypt_crypto_NativeBlockCipher_PADDING_PKCS5 1L
/* Inaccessible static: PADDINGS */
/* Inaccessible static: class_00024javax_00024crypto_00024spec_00024PBEParameterSpec */
/* Inaccessible static: class_00024javax_00024crypto_00024spec_00024IvParameterSpec */
/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    find
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_crypto_NativeBlockCipher_find
  (JNIEnv *, jclass, jstring);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    allocParam
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_beecrypt_crypto_NativeBlockCipher_allocParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    freeParam
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_beecrypt_crypto_NativeBlockCipher_freeParam
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    getBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_beecrypt_crypto_NativeBlockCipher_getBlockSize
  (JNIEnv *, jclass, jlong);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    setup
 * Signature: (JJI[B)V
 */
JNIEXPORT void JNICALL Java_beecrypt_crypto_NativeBlockCipher_setup
  (JNIEnv *, jclass, jlong, jlong, jint, jbyteArray);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    setIV
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL Java_beecrypt_crypto_NativeBlockCipher_setIV
  (JNIEnv *, jclass, jlong, jlong, jbyteArray);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    encryptECB
 * Signature: (JJ[BI[BII)V
 */
JNIEXPORT void JNICALL Java_beecrypt_crypto_NativeBlockCipher_encryptECB
  (JNIEnv *, jclass, jlong, jlong, jbyteArray, jint, jbyteArray, jint, jint);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    decryptECB
 * Signature: (JJ[BI[BII)V
 */
JNIEXPORT void JNICALL Java_beecrypt_crypto_NativeBlockCipher_decryptECB
  (JNIEnv *, jclass, jlong, jlong, jbyteArray, jint, jbyteArray, jint, jint);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    encryptCBC
 * Signature: (JJ[BI[BII)V
 */
JNIEXPORT void JNICALL Java_beecrypt_crypto_NativeBlockCipher_encryptCBC
  (JNIEnv *, jclass, jlong, jlong, jbyteArray, jint, jbyteArray, jint, jint);

/*
 * Class:     beecrypt_crypto_NativeBlockCipher
 * Method:    decryptCBC
 * Signature: (JJ[BI[BII)V
 */
JNIEXPORT void JNICALL Java_beecrypt_crypto_NativeBlockCipher_decryptCBC
  (JNIEnv *, jclass, jlong, jlong, jbyteArray, jint, jbyteArray, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
