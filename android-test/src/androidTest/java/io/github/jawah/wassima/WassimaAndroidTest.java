package io.github.jawah.wassima;

import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.chaquo.python.Python;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class WassimaAndroidTest {
    @Test
    public void readsConscryptNativeCertificates() {
        assertTrue("PyApplication did not start Python", Python.isStarted());
        Python.getInstance().getModule("android_smoke").callAttr("run");
    }
}
