package org.mozilla.gecko.sync.setup;

import org.mozilla.gecko.sync.Logger;
import org.mozilla.gecko.sync.Utils;
import org.mozilla.gecko.sync.repositories.android.Authorities;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

public class AccountCreator {
  private static final String LOG_TAG = "AccountCreator";

  public static Intent createAccount(Context context,
                                     AccountManager accountManager,
                                     String username,
                                     String syncKey,
                                     String password,
                                     String serverURL) {

    final Account account = new Account(username, Constants.ACCOUNTTYPE_SYNC);
    final Bundle userbundle = new Bundle();

    // Add sync key and server URL.
    userbundle.putString(Constants.OPTION_SYNCKEY, syncKey);
    if (serverURL != null) {
      Logger.info(LOG_TAG, "Setting explicit server URL: " + serverURL);
      userbundle.putString(Constants.OPTION_SERVER, serverURL);
    } else {
      userbundle.putString(Constants.OPTION_SERVER, Constants.AUTH_NODE_DEFAULT);
    }
    Logger.info(LOG_TAG, "Adding account for " + Constants.ACCOUNTTYPE_SYNC);
    boolean result = accountManager.addAccountExplicitly(account, password, userbundle);

    Logger.info(LOG_TAG, "Account: " + account.toString() +
                         " added successfully? " + result);
    if (!result) {
      Logger.error(LOG_TAG, "Error adding account!");
    }

    // Set components to sync (default: all).
    ContentResolver.setMasterSyncAutomatically(true);
    ContentResolver.setSyncAutomatically(account, Authorities.BROWSER_AUTHORITY, true);

    // This looks unnecessary, but it resolves Bug 726194.
    ContentResolver.setIsSyncable(account, Authorities.BROWSER_AUTHORITY, 1);

    // TODO: add other ContentProviders as needed (e.g. passwords)
    // TODO: for each, also add to res/xml to make visible in account settings
    Logger.debug(LOG_TAG, "Finished setting syncables.");

    // TODO: correctly implement Sync Options.
    Logger.info(LOG_TAG, "Clearing preferences for this account.");
    try {
      Utils.getSharedPreferences(context, username, serverURL).edit().clear().commit();
    } catch (Exception e) {
      Logger.error(LOG_TAG, "Could not clear prefs path!", e);
    }

    final Intent intent = new Intent();
    intent.putExtra(AccountManager.KEY_ACCOUNT_NAME, username);
    intent.putExtra(AccountManager.KEY_ACCOUNT_TYPE, Constants.ACCOUNTTYPE_SYNC);
    intent.putExtra(AccountManager.KEY_AUTHTOKEN,    Constants.ACCOUNTTYPE_SYNC);
    return intent;
  }
}