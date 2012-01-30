package org.mozilla.android.sync.test.helpers;

import java.util.concurrent.ExecutorService;

import org.mozilla.gecko.sync.repositories.RepositorySession;
import org.mozilla.gecko.sync.repositories.RepositorySessionBundle;
import org.mozilla.gecko.sync.repositories.delegates.RepositorySessionFinishDelegate;

public class DefaultFinishDelegate extends DefaultDelegate implements RepositorySessionFinishDelegate {

  @Override
  public void onFinishFailed(Exception ex) {
    sharedFail("Finish failed");
  }

  @Override
  public void onFinishSucceeded(RepositorySession session, RepositorySessionBundle bundle) {
    sharedFail("Hit default finish delegate");
  }

  @Override
  public RepositorySessionFinishDelegate deferredFinishDelegate(final ExecutorService executor) {
    return new RepositorySessionFinishDelegate() {
      final RepositorySessionFinishDelegate self = this;
      @Override
      public void onFinishSucceeded(final RepositorySession session,
                                    final RepositorySessionBundle bundle) {
        executor.execute(new Runnable() {
          @Override
          public void run() {
            self.onFinishSucceeded(session, bundle);
          }});
      }

      @Override
      public void onFinishFailed(final Exception ex) {
        executor.execute(new Runnable() {
          @Override
          public void run() {
            self.onFinishFailed(ex);
          }});
      }

      @Override
      public RepositorySessionFinishDelegate deferredFinishDelegate(ExecutorService newExecutor) {
        if (newExecutor == executor) {
          return this;
        }
        throw new IllegalArgumentException("Can't re-defer this delegate.");
      }
    };
  }
}