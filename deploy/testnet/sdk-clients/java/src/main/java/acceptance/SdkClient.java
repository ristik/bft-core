package acceptance;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import org.unicitylabs.sdk.api.HttpTrustBaseSource;
import org.unicitylabs.sdk.api.bft.trustbase.CacheDiagnostic;
import org.unicitylabs.sdk.api.bft.trustbase.FlushResult;
import org.unicitylabs.sdk.api.bft.trustbase.MemoryTrustBaseStore;
import org.unicitylabs.sdk.api.bft.trustbase.ReleasePin;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseBundle;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseEntry;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseGapException;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseHistory;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseNetworkException;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseSession;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseSessionOptions;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseSignatureException;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseSource;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseStore;
import org.unicitylabs.sdk.api.bft.trustbase.TrustBaseUpdateOptions;
import org.unicitylabs.sdk.api.bft.trustbase.file.FileTrustBaseStore;
import org.unicitylabs.sdk.util.HexConverter;

/**
 * The public Java SDK's trust-base acceptance client (bft-core #430 row 2): the SDK's own TrustBaseSession + FileTrustBaseStore against a live aggregator.
 * It verifies the trust-base entries the SDK supports; it is NOT a bridge verifier. One JSON object on stdout.
 *   --agg-url URL --network-id N --genesis-pin HEX --genesis FILE --store DIR --mode cold|warm|restart [--negatives DIR]
 *   --negatives DIR   (the offline negatives alone)
 */
public final class SdkClient {

  private static final int MAX_BYTES = 16 * 1024 * 1024;
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final ExecutorService POOL = Executors.newCachedThreadPool(r -> {
    Thread t = new Thread(r);
    t.setDaemon(true);
    return t;
  });

  private SdkClient() {
  }

  public static void main(String[] argv) throws Exception {
    Map<String, String> a = new HashMap<>();
    for (int i = 0; i + 1 < argv.length; i += 2) {
      a.put(argv[i].replaceFirst("^--", ""), argv[i + 1]);
    }
    String commit = System.getenv().getOrDefault("SDK_COMMIT", "unknown");
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("sdk", "java");
    out.put("commit", commit);
    out.put("mode", a.get("mode"));
    int code = 0;
    try {
      if (a.containsKey("mode")) {
        live(a, out);
      }
      if (a.containsKey("negatives")) {
        out.put("negatives", negatives(a.get("negatives")));
      }
    } catch (Throwable e) {
      Throwable cause = unwrap(e);
      out.put("error", cause.getClass().getSimpleName());
      out.put("message", String.valueOf(cause.getMessage()));
      code = 1;
    }
    System.out.println(JSON.writeValueAsString(out));
    System.exit(code);
  }

  private static Throwable unwrap(Throwable e) {
    while ((e instanceof CompletionException || e instanceof java.util.concurrent.ExecutionException) && e.getCause() != null) {
      e = e.getCause();
    }
    return e;
  }

  private static String hex(byte[] b) {
    return HexConverter.encode(b);
  }

  private static TrustBaseSessionOptions options() {
    return TrustBaseSessionOptions.of((Executor) POOL);
  }

  private static TrustBaseSession open(byte[] bundle, TrustBaseStore store) throws Exception {
    return TrustBaseSession.openLocal(bundle, store, options()).get().getSession();
  }

  private static void live(Map<String, String> a, Map<String, Object> out) throws Exception {
    String mode = a.get("mode");
    byte[] genesisBundle = Files.readAllBytes(Paths.get(a.get("genesis")));
    Path dir = Paths.get(a.get("store"));
    if (mode.equals("cold") && Files.exists(dir)) {
      try (Stream<Path> files = Files.list(dir)) {
        if (files.findAny().isPresent()) {
          throw new IllegalStateException("cold needs an empty store");
        }
      }
    }
    TrustBaseStore store = new FileTrustBaseStore(dir, POOL);
    if (mode.equals("warm")) {
      // seed the store through the SDK's own store API with the epoch-1 entry alone (the shipped genesis bundle); the session reopened below must load it
      TrustBaseSession probe = open(genesisBundle, store);
      TrustBaseStore.CasOutcome seeded = store.compareAndSwap(probe.getKey(), null, genesisBundle).get();
      if (seeded != TrustBaseStore.CasOutcome.WRITTEN) {
        throw new IllegalStateException("the warm seed was not written: " + seeded);
      }
    }
    TrustBaseSession.Opened opened = TrustBaseSession.openLocal(genesisBundle, store, options()).get();
    TrustBaseSession session = opened.getSession();
    TrustBaseEntry genesis = session.history().getEntries().get(0);
    out.put("genesisEpoch", genesis.getEpoch());
    if (genesis.getNetworkId().getId() != Integer.parseInt(a.get("network-id"))) {
      throw new IllegalStateException("the genesis is of network " + genesis.getNetworkId().getId() + ", not " + a.get("network-id"));
    }
    if (!hex(genesis.entryId()).equals(a.get("genesis-pin").trim().toLowerCase().replaceFirst("^0x", ""))) {
      throw new IllegalStateException("the shipped genesis is not the pinned EntryID");
    }
    out.put("heldAtOpen", session.history().getEntries().size());
    List<String> diagnostics = new ArrayList<>();
    for (CacheDiagnostic d : opened.getDiagnostics()) {
      diagnostics.add(d.toString());
    }
    out.put("diagnostics", diagnostics);
    List<TrustBaseSource> sources = List.of(new HttpTrustBaseSource(a.get("agg-url"), null));
    int appended = session.refresh(sources, TrustBaseUpdateOptions.defaults()).get();
    out.put("fetched", appended);
    FlushResult flush = session.flush().get();
    Map<String, Object> f = new LinkedHashMap<>();
    f.put("status", flush.isSaved() ? "saved" : "pending");
    if (flush.isSaved()) {
      f.put("wrote", flush.isWrote());
    } else {
      f.put("error", String.valueOf(flush.getError()));
    }
    out.put("flush", f);
    TrustBaseEntry tip = session.getTip().get();
    out.put("tipEpoch", tip.getEpoch());
    Map<String, String> ids = new LinkedHashMap<>();
    for (TrustBaseEntry e : session.history().getEntries()) {
      ids.put(String.valueOf(e.getEpoch()), hex(e.entryId()));
    }
    out.put("entryIds", ids);
    // what the store holds now, re-verified strictly from the pin by the SDK's own decoder
    TrustBaseStore.Stored stored = store.read(session.getKey(), MAX_BYTES).get().orElseThrow(() -> new IllegalStateException("the store holds nothing after the flush"));
    TrustBaseHistory reloaded = TrustBaseHistory.fromBundle(TrustBaseBundle.decode(stored.getBytes(), ReleasePin.DEFAULT_LIMITS), genesis.entryId());
    List<TrustBaseEntry> back = reloaded.getEntries();
    out.put("persisted", back.size() == ids.size() && Arrays.equals(back.get(back.size() - 1).entryId(), tip.entryId()));
  }

  private interface Offer {
    Object run() throws Exception;
  }

  private static Map<String, Object> negatives(String dir) throws Exception {
    Map<String, Object> res = new LinkedHashMap<>();
    byte[] genesis = Files.readAllBytes(Paths.get(dir, "genesis.bundle.cbor"));
    byte[] other = Files.readAllBytes(Paths.get(dir, "genesis.othernet.bundle.cbor"));

    // 1. missing middle, nothing fetched: the session holds the genesis only and is offered the epoch-3 entry
    TrustBaseSession s = open(genesis, new MemoryTrustBaseStore());
    Map<String, Object> r = tried(s, dir, "entry-3.cbor", TrustBaseGapException.class);
    s = open(genesis, new MemoryTrustBaseStore());
    final TrustBaseSession c1 = s;
    r.put("control", control(s, () -> List.of(c1.append(entry(dir, "entry-2.cbor")).name(), c1.append(entry(dir, "entry-3.cbor")).name())));
    res.put("missingMiddle", r);

    // 2. entry 2 with its signatures reduced below the predecessor's quorum
    s = open(genesis, new MemoryTrustBaseStore());
    r = tried(s, dir, "entry-2.weak.cbor", TrustBaseSignatureException.class);
    s = open(genesis, new MemoryTrustBaseStore());
    final TrustBaseSession c2 = s;
    r.put("control", control(s, () -> c2.append(entry(dir, "entry-2.cbor")).name()));
    res.put("belowQuorum", r);

    // 3. a session of another network than the entries' (its genesis is the real genesis with another network id)
    s = open(other, new MemoryTrustBaseStore());
    r = tried(s, dir, "entry-2.cbor", TrustBaseNetworkException.class);
    s = open(genesis, new MemoryTrustBaseStore());
    final TrustBaseSession c3 = s;
    r.put("control", control(s, () -> c3.append(entry(dir, "entry-2.cbor")).name()));
    res.put("wrongNetwork", r);
    return res;
  }

  private static TrustBaseEntry entry(String dir, String name) throws Exception {
    return TrustBaseEntry.decode(Files.readAllBytes(Paths.get(dir, name)));
  }

  private static Map<String, Object> tried(TrustBaseSession s, String dir, String name, Class<? extends Throwable> expected) throws Exception {
    Map<String, Object> r = new LinkedHashMap<>();
    try {
      r.put("outcome", s.append(entry(dir, name)).name());
      r.put("refused", false);
    } catch (RuntimeException e) {
      r.put("refused", true);
      r.put("error", e.getClass().getSimpleName());
      r.put("typed", expected.isInstance(e));
      String m = String.valueOf(e.getMessage());
      r.put("message", m.substring(0, Math.min(160, m.length())));
    }
    r.put("tipAfter", s.getTip().get().getEpoch());
    return r;
  }

  private static Map<String, Object> control(TrustBaseSession s, Offer offer) {
    Map<String, Object> r = new LinkedHashMap<>();
    try {
      r.put("accepted", true);
      r.put("outcome", offer.run());
      r.put("tipAfter", s.getTip().get().getEpoch());
    } catch (Exception e) {
      r.put("accepted", false);
      r.put("error", e.getClass().getSimpleName());
      r.put("message", String.valueOf(e.getMessage()));
    }
    return r;
  }
}
