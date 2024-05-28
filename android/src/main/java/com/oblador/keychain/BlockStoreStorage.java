package com.oblador.keychain;

import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.ReactApplicationContext;
import com.google.android.gms.auth.blockstore.Blockstore;
import com.google.android.gms.auth.blockstore.BlockstoreClient;
import com.google.android.gms.auth.blockstore.DeleteBytesRequest;
import com.google.android.gms.auth.blockstore.RetrieveBytesRequest;
import com.google.android.gms.auth.blockstore.RetrieveBytesResponse;
import com.google.android.gms.auth.blockstore.RetrieveBytesResponse.BlockstoreData;
import com.google.android.gms.auth.blockstore.StoreBytesData;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.oblador.keychain.KeychainModule.KnownCiphers;
import com.oblador.keychain.cipherStorage.CipherStorage.EncryptionResult;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@SuppressWarnings({"unused", "WeakerAccess"})
public class BlockStoreStorage implements KeyValueStorage {
  public static final String KEYCHAIN_DATA = "RN_KEYCHAIN";
  public static final String TAG = "BlockStoreStorage";

  @NonNull
  private final BlockstoreClient blockstoreClient;

  public BlockStoreStorage(@NonNull final ReactApplicationContext reactContext) {
    blockstoreClient = Blockstore.getClient(reactContext);
  }

  @Nullable
  public ResultSet getEncryptedEntry(@NonNull final String service) {
    String usernameKey = getKeyForUsername(service);
    String passwordKey = getKeyForPassword(service);
    String cipherStorageKey = getKeyForCipherStorage(service);

    RetrieveBytesRequest retrieveRequest = createRetrieveRequest(usernameKey, passwordKey, cipherStorageKey);
    Task<RetrieveBytesResponse> task = blockstoreClient.retrieveBytes(retrieveRequest)
      .addOnSuccessListener(__ -> Log.d(TAG, "getEncryptedEntry: Fetching keys=(" + usernameKey + "," + passwordKey + "," + cipherStorageKey + ") from BlockStore API SUCCEEDED."))
      .addOnFailureListener(error -> Log.e(TAG, "getEncryptedEntry: Fetching keys=(" + usernameKey + "," + passwordKey + "," + cipherStorageKey + ") from BlockStore API FAILED: " + error.getMessage()));

    try {
      Map<String, BlockstoreData> blockstoreData = Tasks.await(task).getBlockstoreDataMap();

      BlockstoreData usernameData = blockstoreData.get(usernameKey);
      byte[] username = usernameData != null ? usernameData.getBytes() : null;
//      byte[] username = usernameData != null ? Base64.decode(usernameData.getBytes(), Base64.DEFAULT) : null;

      BlockstoreData passwordData = blockstoreData.get(passwordKey);
      byte[] password = passwordData != null ? passwordData.getBytes() : null;
//      byte[] password = passwordData != null ? Base64.decode(passwordData.getBytes(), Base64.DEFAULT) : null;

      // in case of wrong password or username
      if (username == null || password == null) {
        Log.e(TAG, "getEncryptedEntry: RETURNING NULL as username=" + username + ", password="+password);
        return null;
      }

      BlockstoreData cipherStorageData = blockstoreData.get(cipherStorageKey);
      String cipherStorageName = cipherStorageData != null ? new String(cipherStorageData.getBytes(), StandardCharsets.UTF_8) : null;
      if (cipherStorageName == null) {
        // If the CipherStorage name is not found, we assume it is because the entry was written by an older
        // version of this library. The older version used Facebook Conceal, so we default to that.
        cipherStorageName = KnownCiphers.FB;
      }
      Log.e(TAG, "getEncryptedEntry: ResultSet("+cipherStorageName+","+new String(Base64.decode(username, Base64.DEFAULT))+","+new String(Base64.decode(password, Base64.DEFAULT))+")"); //todo: remove LOG
      return new ResultSet(cipherStorageName, username, password);
    } catch (Exception exception) {
      Log.e(TAG, "getEncryptedEntry: Awaiting for BlockStore API task failed: " + exception.getMessage());
      return null;
    }
  }

  public void removeEntry(@NonNull final String service) {
    final String keyForUsername = getKeyForUsername(service);
    final String keyForPassword = getKeyForPassword(service);
    final String keyForCipherStorage = getKeyForCipherStorage(service);
    DeleteBytesRequest request = createDeleteRequest(keyForUsername, keyForPassword, keyForCipherStorage);
    blockstoreClient.deleteBytes(request)
      .addOnSuccessListener(__ -> Log.d(TAG, "Removing keys=" + keyForUsername + "," + keyForPassword + "," + keyForCipherStorage + ") from BlockStore API SUCCEEDED."))
      .addOnFailureListener(error -> Log.e(TAG, "Removing keys=" + keyForUsername + "," + keyForPassword + "," + keyForCipherStorage + ") from BlockStore API FAILED: " + error.getMessage()));
  }

  public void storeEncryptedEntry(@NonNull final String service, @NonNull final EncryptionResult encryptionResult) {
    // Username
    final String keyForUsername = getKeyForUsername(service);
    final byte[] valueForUsername = Base64.encode(encryptionResult.username, Base64.DEFAULT);
    StoreBytesData usernameRequest = createSaveRequest(keyForUsername, valueForUsername);
    blockstoreClient
      .storeBytes(usernameRequest)
      .addOnSuccessListener(result -> Log.d(TAG, "Saving key=" + keyForUsername + " to BlockStore API SUCCEEDED, wrote " + result + " bytes."))
      .addOnFailureListener(error -> Log.e(TAG, "Saving key=" + keyForUsername + " to BlockStore API FAILED: " + error));

    // Password
    final String keyForPassword = getKeyForPassword(service);
    final byte[] valueForPassword = Base64.encode(encryptionResult.password, Base64.DEFAULT);
    StoreBytesData passwordRequest = createSaveRequest(keyForPassword, valueForPassword);
    blockstoreClient
      .storeBytes(passwordRequest)
      .addOnSuccessListener(result -> Log.d(TAG, "Saving key=" + keyForPassword + " to BlockStore API SUCCEEDED, wrote " + result + " bytes."))
      .addOnFailureListener(error -> Log.e(TAG, "Saving key=" + keyForPassword + " to BlockStore API FAILED: " + error));

    // Cipher Storage
    final String keyForCipherStorage = getKeyForCipherStorage(service);
    final byte[] valueForCipherStorage = encryptionResult.cipherName.getBytes(StandardCharsets.UTF_8);
    StoreBytesData cipherStorageRequest = createSaveRequest(keyForCipherStorage, valueForCipherStorage);
    blockstoreClient
      .storeBytes(cipherStorageRequest)
      .addOnSuccessListener(result -> Log.d(TAG, "Saving key=" + keyForCipherStorage + " to BlockStore API SUCCEEDED, wrote " + result + " bytes."))
      .addOnFailureListener(error -> Log.e(TAG, "Saving key=" + keyForCipherStorage + " to BlockStore API FAILED: " + error));
  }

  /**
   * List all types of cipher which are involved in en/decryption of the data stored herein.
   *
   * A cipher type is stored together with the datum upon encryption so the datum can later be decrypted using correct
   * cipher. This way, a {@link BlockStoreStorage} can involve different ciphers for different data. This method returns all
   * ciphers involved with this storage.
   *
   * @return set of cipher names
   */
  public Set<String> getUsedCipherNames() {
    RetrieveBytesRequest request = createRetrieveAllRequest();
    Task<RetrieveBytesResponse> task = blockstoreClient.retrieveBytes(request);
    Map<String, BlockstoreData> dataMap;
    Set<String> keys = new HashSet<>();
    try {
      dataMap = Tasks.await(task).getBlockstoreDataMap();
    } catch (Exception exception) {
      Log.e(TAG, "Awaiting for BlockStore API task inside getAllKeys() failed: " + exception.getMessage());
      return keys;
    }

    for (String key : dataMap.keySet()) {
      if (isKeyForCipherStorage(key) && dataMap.get(key) != null) {
        String cipher = new String(dataMap.get(key).getBytes(), StandardCharsets.UTF_8);
        keys.add(cipher);
      }
    }
    return keys;
  }

  @NonNull
  public static String getKeyForUsername(@NonNull final String service) {
    return service + ":" + "u";
  }

  @NonNull
  public static String getKeyForPassword(@NonNull final String service) {
    return service + ":" + "p";
  }

  @NonNull
  public static String getKeyForCipherStorage(@NonNull final String service) {
    return service + ":" + "c";
  }

  public static boolean isKeyForCipherStorage(@NonNull final String key) {
    return key.endsWith(":c");
  }

  // --------

  private StoreBytesData createSaveRequest(String key, byte[] bytes) {

    // flag should have been already updated async in constructor, but just in case the request failed, update it again now
//    if (isE2EEncryptionAvailable == null) {
//      updateE2EEncryptionAvailabilityFlag();
//    }

//    boolean setShouldBackupToCloud = isE2EEncryptionAvailable != null && isE2EEncryptionAvailable;

    return new StoreBytesData.Builder()
      .setShouldBackupToCloud(true) // todo: update base ond e2e encryption availability!
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
}
