package com.google.crypto.tink.tinkey;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.signature.MlDsaSignKeyManager;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SlhDsaSignKeyManager;
import com.google.crypto.tink.signature.internal.MlDsaSignConscrypt;
import com.google.crypto.tink.signature.internal.SlhDsaSignConscrypt;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.security.Security;
import java.util.Base64;
import java.util.TreeSet;
import org.conscrypt.Conscrypt;

/**
 * Prints every key template of Java Tinkey as "NAME base64(KeyTemplate proto)", one per line.
 *
 * <p>It lives in Tinkey's package to reach the package-private TinkeyKeyTemplates, and registers
 * the same key types, in the same order, as Tinkey.main. Its output is
 * cmd/tinkey/java_key_templates.txt; see the Makefile target java-key-templates.
 */
public final class DumpKeyTemplates {
  public static void main(String[] args) throws Exception {
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());

    DeterministicAeadConfig.register();
    HybridConfig.register();
    PrfConfig.register();
    SignatureConfig.register();
    if (MlDsaSignConscrypt.isSupported()) {
      MlDsaSignKeyManager.registerPair();
    }
    if (SlhDsaSignConscrypt.isSupported()) {
      SlhDsaSignKeyManager.registerPair();
    }
    StreamingAeadConfig.register();
    JwtSignatureConfig.register();
    JwtMacConfig.register();
    KeyDerivationConfig.register();

    TreeSet<String> names = new TreeSet<>(Registry.keyTemplates());
    names.addAll(TinkeyKeyTemplates.get().keySet());
    for (String name : names) {
      // The same lookup order as Tinkey's KeyTemplateHandler.
      KeyTemplate template = TinkeyKeyTemplates.get().get(name);
      if (template == null) {
        template = KeyTemplates.get(name);
      }
      byte[] serialized = TinkProtoParametersFormat.serialize(template.toParameters());
      System.out.println(name + " " + Base64.getEncoder().encodeToString(serialized));
    }
  }

  private DumpKeyTemplates() {}
}
