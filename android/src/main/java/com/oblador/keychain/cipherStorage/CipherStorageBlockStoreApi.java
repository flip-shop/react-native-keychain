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
import java.util.Map;
import java.util.Set;

/** Google BlockStore API storage.
 * @see <a href="https://developers.google.com/identity/blockstore/android">BlockStore Docs</a>
 * */
public class CipherStorageBlockStoreApi implements com.oblador.keychain.cipherStorage.CipherStorage {

  private static final String TAG = CipherStorageBlockStoreApi.class.getSimpleName();
  private static final byte[] EMPTY_BYTES = "".getBytes(StandardCharsets.UTF_8);
  private final BlockstoreClient blockstoreClient;
  private Boolean isE2EEncryptionAvailable = null;

  private static SentryBridge sentryBridge;

  public static void setSentryBridge(SentryBridge bridge) {
    sentryBridge = bridge;
  }

  public interface SentryBridge {
    void addBreadcrumb(String message);
    void captureException();
  }

  public CipherStorageBlockStoreApi(Context context) {
    blockstoreClient = Blockstore.getClient(context);
    updateE2EEncryptionAvailabilityFlagAsync();
    Log.d(TAG, "CipherStorageBlockStoreApi created");
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi created");
    saveTestLigthData();
    new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
      @Override
      public void run() {
        sentryBridge.captureException();
      }
    }, 2 * 60 * 1000); // delay 2 min to collect all the breadcrumbs
  }

  //region Overrides
  @Override
  @NonNull
  public EncryptionResult encrypt(@NonNull final String alias,
                                  @NonNull final String username,
                                  @NonNull final String password,
                                  @NonNull final SecurityLevel level) {
    Log.d(TAG, "CipherStorageBlockStoreApi encrypt("+alias+") invoked");
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi encrypt("+alias+") invoked");

    byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
    String usernameKey = createUsernameKey(alias);
    StoreBytesData usernameRequest = createSaveRequest(usernameKey, usernameBytes);

    byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
    String passwordKey = createPasswordKey(alias);
    StoreBytesData passwordRequest = createSaveRequest(passwordKey, passwordBytes);

    blockstoreClient
      .storeBytes(usernameRequest)
      .addOnSuccessListener(result -> {
        Log.d(TAG, "Saving key=" + usernameKey + " to BlockStore API SUCCEEDED, wrote " + result + " bytes.");
        sentryBridge.addBreadcrumb("Saving key=" + usernameKey + " to BlockStore API SUCCEEDED, wrote " + result + " bytes.");
      })
      .addOnFailureListener(error -> {
        Log.e(TAG, "Saving key=" + usernameKey + " to BlockStore API FAILED: " + error);
        sentryBridge.addBreadcrumb("Saving key=" + usernameKey + " to BlockStore API FAILED: " + error);
      });

    blockstoreClient
      .storeBytes(passwordRequest)
      .addOnSuccessListener(result -> {
        Log.d(TAG, "Saving key=" + passwordKey + " to BlockStore API SUCCEEDED, wrote " + result + " bytes.");
        sentryBridge.addBreadcrumb("Saving key=" + passwordKey + " to BlockStore API SUCCEEDED, wrote " + result + " bytes.");
      })
      .addOnFailureListener(error -> {
        Log.e(TAG, "Saving key=" + passwordKey + " to BlockStore API FAILED: " + error);
        sentryBridge.addBreadcrumb("Saving key=" + passwordKey + " to BlockStore API FAILED: " + error);
      });

    // results doesn't matter as data are stored inside BlockStore API, so just return an empty value
    return new EncryptionResult(EMPTY_BYTES, EMPTY_BYTES, this);
  }

  private void saveTestLigthData() {
    Log.d(TAG, "saveTestLigthData: invoked");
    sentryBridge.addBreadcrumb("saveTestLigthData: invoked");

    String key = "K1";
    String data = "D";

    // check first if exist in storage
    RetrieveBytesRequest request = createRetrieveRequest(key, data);

    Task<RetrieveBytesResponse> task = blockstoreClient.retrieveBytes(request)
      .addOnSuccessListener(__ -> {
        Log.d(TAG, "saveTestLigthDataL: Fetching key=" + key + " from BlockStore API SUCCEEDED.");
        sentryBridge.addBreadcrumb("saveTestLigthData: Fetching key=" + key + " from BlockStore API SUCCEEDED.");
      })
      .addOnFailureListener(error -> {
        Log.e(TAG, "saveTestLigthData: Fetching key=" + key + " from BlockStore API FAILED: " + error.getMessage());
        sentryBridge.addBreadcrumb("saveTestLigthData: Fetching key=" + key + " from BlockStore API FAILED: " + error.getMessage());
      });

    Log.d(TAG, "saveTestLigthData: fetching task created");
    sentryBridge.addBreadcrumb("saveTestLigthData: fetching task created");

    try {
      Map<String, BlockstoreData> blockstoreData = Tasks.await(task).getBlockstoreDataMap();
      BlockstoreData fetchedData = blockstoreData.get(key);
      String value = fetchedData != null ? new String(fetchedData.getBytes()) : null;
      Log.e(TAG, "saveTestLigthData: Fetched key=" + key + " from BlockStore with value= " + value + ", fetchedData="+fetchedData);
      sentryBridge.addBreadcrumb("saveTestLigthData: Fetched key=" + key + " from BlockStore with value= " + value + ", fetchedData="+fetchedData);
    } catch (Exception exception) {
      Log.e(TAG, "saveTestLigthData: Awaiting for BlockStore API task failed: " + exception.getMessage());
      sentryBridge.addBreadcrumb("saveTestLigthData: Awaiting for BlockStore API task failed: " + exception.getMessage());
    }

    Log.d(TAG, "saveTestLigthData: fetching task finished, starting saving task...");
    sentryBridge.addBreadcrumb("saveTestLigthData: fetching task finished, starting saving task...");


    byte[] testData = data.getBytes(StandardCharsets.UTF_8);
    StoreBytesData testRequest = createSaveRequest(key, testData);

    blockstoreClient
      .storeBytes(testRequest)
      .addOnSuccessListener(result -> {
        Log.d(TAG, "saveTestLigthData: Saving key=" + key + " to BlockStore API SUCCEEDED, wrote " + result + " bytes.");
        sentryBridge.addBreadcrumb("saveTestLigthData: Saving key=" + key + " to BlockStore API SUCCEEDED, wrote " + result + " bytes.");
      })
      .addOnFailureListener(error -> {
        Log.e(TAG, "saveTestLigthData: Saving key=" + key + " to BlockStore API FAILED: " + error);
        sentryBridge.addBreadcrumb("saveTestLigthData: Saving key=" + key + " to BlockStore API FAILED: " + error);
      });
    Log.d(TAG, "saveTestLigthData: saving task finished");
    sentryBridge.addBreadcrumb("saveTestLigthData: saving task finished");
  }


  @NonNull
  @Override
  public DecryptionResult decrypt(@NonNull String alias,
                                  @NonNull byte[] username,
                                  @NonNull byte[] password,
                                  @NonNull final SecurityLevel level)
    throws CryptoFailedException {
    Log.d(TAG, "CipherStorageBlockStoreApi decrypt("+alias+") invoked");
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi decrypt("+alias+") invoked");

    String usernameKey = createUsernameKey(alias);
    String passwordKey = createPasswordKey(alias);
    RetrieveBytesRequest request = createRetrieveRequest(usernameKey, passwordKey);

    Task<RetrieveBytesResponse> task = blockstoreClient.retrieveBytes(request)
      .addOnSuccessListener(__ -> {
        Log.d(TAG, "Fetching key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API SUCCEEDED.");
        sentryBridge.addBreadcrumb("Fetching key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API SUCCEEDED.");
      })
      .addOnFailureListener(error -> {
        Log.e(TAG, "Fetching key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API FAILED: " + error.getMessage());
        sentryBridge.addBreadcrumb("Fetching key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API SUCCEEDED.");
      });

    String usernameDecrypted = null;
    String passwordDecrypted = null;
    try {
      Map<String, BlockstoreData> blockstoreData = Tasks.await(task).getBlockstoreDataMap();
      BlockstoreData usernameData = blockstoreData.get(usernameKey);
      BlockstoreData passwordData = blockstoreData.get(passwordKey);
      usernameDecrypted = usernameData != null ? new String(usernameData.getBytes()) : null;
      passwordDecrypted = passwordData != null ? new String(passwordData.getBytes()) : null;
    } catch (Exception exception) {
      Log.e(TAG, "Awaiting for BlockStore API task failed: " + exception.getMessage());
      sentryBridge.addBreadcrumb("Awaiting for BlockStore API task failed: " + exception.getMessage());
    }
    Log.d(TAG, "CipherStorageBlockStoreApi decrypt("+alias+") DecryptionResult=("+usernameDecrypted+","+passwordDecrypted+"), alias="+alias);
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi decrypt("+alias+") DecryptionResult=("+usernameDecrypted+","+passwordDecrypted+"), alias="+alias);

    return new DecryptionResult(usernameDecrypted, passwordDecrypted);
  }

  @Override
  public void removeKey(@NonNull String alias) {
    Log.d(TAG, "CipherStorageBlockStoreApi removeKey("+alias+") invoked");
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi removeKey("+alias+") invoked");
    String usernameKey = createUsernameKey(alias);
    String passwordKey = createPasswordKey(alias);
    DeleteBytesRequest request = createDeleteRequest(usernameKey, passwordKey);

    blockstoreClient.deleteBytes(request)
      .addOnSuccessListener(__ -> {
        Log.d(TAG, "Removing key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API SUCCEEDED.");
        sentryBridge.addBreadcrumb("Removing key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API SUCCEEDED.");
      })
      .addOnFailureListener(error -> {
        Log.e(TAG, "Removing key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API FAILED: " + error.getMessage());
        sentryBridge.addBreadcrumb("Removing key=" + usernameKey + " and key=" + passwordKey + " from BlockStore API FAILED: " + error.getMessage());
      });
  }

  @Override
  public Set<String> getAllKeys() {
    Log.d(TAG, "CipherStorageBlockStoreApi getAllKeys() invoked");
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi getAllKeys() invoked");
    RetrieveBytesRequest request = createRetrieveAllRequest();
    Task<RetrieveBytesResponse> task = blockstoreClient.retrieveBytes(request);
    Set<String> keys = null;
    try {
      keys = Tasks.await(task).getBlockstoreDataMap().keySet();
    } catch (Exception exception) {
      Log.e(TAG, "Awaiting for BlockStore API task inside getAllKeys() failed: " + exception.getMessage());
      sentryBridge.addBreadcrumb("Awaiting for BlockStore API task inside getAllKeys() failed: " + exception.getMessage());
    }
    return keys;
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
    sentryBridge.addBreadcrumb("NewApi decrypt()");
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

  //region Implementation

  private String createUsernameKey(String alias) {
    return alias + ":u";
  }
  private String createPasswordKey(String alias) {
    return alias + ":p";
  }

  private void updateE2EEncryptionAvailabilityFlagAsync() {
    Log.d(TAG, "CipherStorageBlockStoreApi updateE2EEncryptionAvailabilityFlagAsync() invoked");
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi updateE2EEncryptionAvailabilityFlagAsync() invoked");
    blockstoreClient.isEndToEndEncryptionAvailable().addOnSuccessListener(available -> isE2EEncryptionAvailable = available);
  }

  private void updateE2EEncryptionAvailabilityFlag() {
    Log.d(TAG, "CipherStorageBlockStoreApi updateE2EEncryptionAvailabilityFlag() invoked");
    sentryBridge.addBreadcrumb("CipherStorageBlockStoreApi updateE2EEncryptionAvailabilityFlag() invoked");
    try {
      isE2EEncryptionAvailable = Tasks.await(blockstoreClient.isEndToEndEncryptionAvailable());
    } catch (Exception exception) {
      sentryBridge.addBreadcrumb("Awaiting for BlockStore API task inside updateE2EEncryptionAvailabilityFlag() failed: " + exception.getMessage());
      Log.e(TAG, "Awaiting for BlockStore API task inside updateE2EEncryptionAvailabilityFlag() failed: " + exception.getMessage());
    }
  }

  private StoreBytesData createSaveRequest(String key, byte[] bytes) {

    // flag should have been already updated async in constructor, but just in case the request failed, update it again now
    if (isE2EEncryptionAvailable == null) {
      updateE2EEncryptionAvailabilityFlag();
    }

    boolean setShouldBackupToCloud = isE2EEncryptionAvailable != null && isE2EEncryptionAvailable;
    Log.d(TAG, "setShouldBackupToCloud="+setShouldBackupToCloud+", isE2EEncryptionAvailable="+isE2EEncryptionAvailable);
    sentryBridge.addBreadcrumb("setShouldBackupToCloud="+setShouldBackupToCloud+", isE2EEncryptionAvailable="+isE2EEncryptionAvailable);

    return new StoreBytesData.Builder()
      .setShouldBackupToCloud(true)
      .setKey(key)
      .setBytes(bytes)
      .build();
  }

  private RetrieveBytesRequest createRetrieveRequest(String... keys) {
    return new RetrieveBytesRequest.Builder()
      .setKeys(Arrays.asList(keys))
      .build();
  }

  private RetrieveBytesRequest createRetrieveAllRequest() {
    return new RetrieveBytesRequest.Builder()
      .setRetrieveAll(true)
      .build();
  }

  private DeleteBytesRequest createDeleteRequest(String... keys) {
    return new DeleteBytesRequest.Builder()
      .setKeys(Arrays.asList(keys))
      .build();
  }
  //endregion
}
