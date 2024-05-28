package com.oblador.keychain.cipherStorage;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;

import com.google.android.gms.auth.blockstore.Blockstore;
import com.google.android.gms.auth.blockstore.BlockstoreClient;
import com.google.android.gms.auth.blockstore.DeleteBytesRequest;
import com.google.android.gms.auth.blockstore.RetrieveBytesRequest;
import com.google.android.gms.auth.blockstore.RetrieveBytesResponse;
import com.google.android.gms.auth.blockstore.RetrieveBytesResponse.BlockstoreData;
import com.google.android.gms.auth.blockstore.StoreBytesData;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.oblador.keychain.KeychainModule;
import com.oblador.keychain.SecurityLevel;
import com.oblador.keychain.decryptionHandler.DecryptionResultHandler;
import com.oblador.keychain.exceptions.CryptoFailedException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Google BlockStore API storage.
 * @see <a href="https://developers.google.com/identity/blockstore/android">BlockStore Docs</a>
 * */
public class CipherStorageBlockStoreApi implements com.oblador.keychain.cipherStorage.CipherStorage {

  private static final String TAG = CipherStorageBlockStoreApi.class.getSimpleName();

  public CipherStorageBlockStoreApi(Context context) {
    Log.d(TAG, "CipherStorageBlockStoreApi created");
  }

  //region Overrides
  @Override
  @NonNull
  public EncryptionResult encrypt(@NonNull final String alias,
                                  @NonNull final String username,
                                  @NonNull final String password,
                                  @NonNull final SecurityLevel level) {
    Log.d(TAG, "CipherStorageBlockStoreApi encrypt("+alias+") invoked");

    byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
    byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
    return new EncryptionResult(usernameBytes, passwordBytes, this);
  }



  @NonNull
  @Override
  public DecryptionResult decrypt(@NonNull String alias,
                                  @NonNull byte[] username,
                                  @NonNull byte[] password,
                                  @NonNull final SecurityLevel level)
    throws CryptoFailedException {
    Log.d(TAG, "CipherStorageBlockStoreApi decrypt("+alias+") invoked");

    String usernameDecrypted = new String(username, StandardCharsets.UTF_8);
    String passwordDecrypted = new String(password, StandardCharsets.UTF_8);
    return new DecryptionResult(usernameDecrypted, passwordDecrypted);
  }

  @Override
  public void removeKey(@NonNull String alias) {
    Log.d(TAG, "CipherStorageBlockStoreApi removeKey("+alias+") invoked");
    // nothing to remove
  }

  @Override
  public Set<String> getAllKeys() {
    return new HashSet<>();
  }

  @Override
  public SecurityLevel securityLevel() {
    return SecurityLevel.SECURE_SOFTWARE;
  }

  @Override
  public boolean supportsSecureHardware() {
    return false;
  }

  /**
   * COPY PASTE FROM [com.oblador.keychain.cipherStorage.CipherStorageBase]
   * The higher value means better capabilities. Range: [19..1129].
   * Formula: `1000 * isBiometrySupported() + 100 * isSecureHardware() + minSupportedApiLevel()`
   */
  @Override
  public int getCapabilityLevel() {
    return
      (1000 * (isBiometrySupported() ? 1 : 0)) + // 0..1000
        (getMinSupportedApiLevel()); // 19..29
  }

  @Override
  public String getDefaultAliasServiceName() {
    return KeychainModule.KnownCiphers.BS;
  }

  @Override
  public String getCipherStorageName() {
    return KeychainModule.KnownCiphers.BS;
  }

  @Override
  @SuppressLint("NewApi")
  public void decrypt(@NonNull DecryptionResultHandler handler,
                      @NonNull String alias,
                      @NonNull byte[] username,
                      @NonNull byte[] password,
                      @NonNull final SecurityLevel level)
    throws CryptoFailedException {
    handler.onDecrypt(decrypt(alias, username, password, level), null);
    Log.d(TAG, "NewApi decrypt()");
  }

  //endregion

  //region Configuration

  /** API28 is a requirement for End-to-end encryption, so don't support lower levels. */
  @Override
  public int getMinSupportedApiLevel() {
    return Build.VERSION_CODES.P;
  }

  @Override
  public boolean isBiometrySupported() {
    return false;
  }

  //endregion
}
