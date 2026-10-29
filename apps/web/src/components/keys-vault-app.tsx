"use client";

import { useAuth, UserButton } from "@clerk/nextjs";
import {
  createVault,
  createVaultAttachment,
  readVaultAttachment,
  MAX_FILE_BYTES,
  MAX_ENVELOPE_BYTES,
  type VaultAttachment,
  destroyVaultKey,
  encryptVaultPayload,
  recoverVault,
  rekeyVault,
  unlockVault,
  validateVaultEnvelope,
  type VaultEnvelope,
  type VaultEnvironment,
  type VaultItem,
  type VaultPayload,
} from "@vaultroom/crypto";
import {
  Check,
  Clipboard,
  Clock3,
  CloudOff,
  Download,
  Eye,
  EyeOff,
  FileKey2,
  Fingerprint,
  KeyRound,
  Lock,
  LoaderCircle,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Search,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { apiRequest } from "@/lib/api";
import { loadLocalVault, saveLocalVault } from "@/lib/vault-storage";
import { SecurityExplainer } from "@/components/security-explainer";

type Phase = "loading" | "setup" | "recovery" | "locked" | "unlocked";
type EditorState = VaultItem | "new" | null;
type SyncState = "loading" | "synced" | "saving" | "offline" | "conflict" | "local";
type CloudVaultResponse = {
  vault: { revision: number; envelope: VaultEnvelope; updatedAt: string } | null;
};

const environments: VaultEnvironment[] = ["development", "staging", "production", "personal"];

function formatDate(value: string | null) {
  if (!value) return "No expiry";
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric" }).format(
    new Date(value),
  );
}

function downloadText(name: string, text: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function KeysVaultApp() {
  const { getToken, userId } = useAuth();
  const [phase, setPhase] = useState<Phase>("loading");
  const [envelope, setEnvelope] = useState<VaultEnvelope | null>(null);
  const [payload, setPayload] = useState<VaultPayload | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);
  const [recoveryKey, setRecoveryKey] = useState("");
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [recoveryReplaced, setRecoveryReplaced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<VaultEnvironment | "all">("all");
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<EditorState>(null);
  const [cloudRevision, setCloudRevision] = useState(0);
  const [syncState, setSyncState] = useState<SyncState>("loading");
  const [railCompact, setRailCompact] = useState(false);
  const session = useRef(0);
  const mutation = useRef(false);
  const [manageEnvironments, setManageEnvironments] = useState(false);
  const vaultEnvironments = payload?.environments ?? environments;
  const importRef = useRef<HTMLInputElement>(null);
  // After a rekey the server must drop its older envelopes; kept until a push succeeds.
  const historyResetPending = useRef(false);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      setRailCompact(window.localStorage.getItem("vaultroom-rail-compact") === "true");
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    if (!userId) return;
    let cancelled = false;
    void (async () => {
      try {
        const local = await loadLocalVault(userId);
        const remote = await apiRequest<CloudVaultResponse>(getToken, "/vault");
        if (cancelled) return;
        const useRemote = remote.vault && (!local || remote.vault.revision > local.cloudRevision);
        const selectedEnvelope = useRemote ? remote.vault!.envelope : local?.envelope ?? null;
        const selectedRevision = useRemote ? remote.vault!.revision : local?.cloudRevision ?? 0;
        if (useRemote) await saveLocalVault(userId, { envelope: selectedEnvelope!, cloudRevision: selectedRevision });
        historyResetPending.current = !useRemote && Boolean(local?.resetHistoryPending);
        setEnvelope(selectedEnvelope);
        setCloudRevision(selectedRevision);
        setSyncState(remote.vault || local ? "synced" : "local");
        setPhase(selectedEnvelope ? "locked" : "setup");
      } catch (nextError) {
        const local = await loadLocalVault(userId).catch(() => null);
        if (cancelled) return;
        historyResetPending.current = Boolean(local?.resetHistoryPending);
        setEnvelope(local?.envelope ?? null);
        setCloudRevision(local?.cloudRevision ?? 0);
        setSyncState("offline");
        setError(nextError instanceof Error ? nextError.message : "Cloud backup is unavailable");
        setPhase(local ? "locked" : "setup");
      }
    })();
    return () => { cancelled = true; };
  }, [getToken, userId]);

  useEffect(() => {
    if (phase !== "unlocked" || !vaultKey) return;
    let timer = window.setTimeout(() => void lock(), 10 * 60 * 1000);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void lock(), 10 * 60 * 1000);
    };
    const events = ["pointerdown", "keydown"] as const;
    events.forEach((event) => window.addEventListener(event, reset, { passive: true }));
    return () => {
      window.clearTimeout(timer);
      events.forEach((event) => window.removeEventListener(event, reset));
    };
  });

  const visibleItems = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return (payload?.items ?? [])
      .filter((item) => filter === "all" || item.environment === filter)
      .filter(
        (item) =>
          !normalized ||
          item.service.toLowerCase().includes(normalized) ||
          item.label.toLowerCase().includes(normalized) ||
          item.notes.toLowerCase().includes(normalized),
      )
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }, [filter, payload, query]);

  async function lock() {
    session.current++;
    setManageEnvironments(false);
    if (vaultKey) await destroyVaultKey(vaultKey);
    setVaultKey(null);
    setPayload(null);
    setRevealed(new Set());
    setEditor(null);
    setPhase(envelope ? "locked" : "setup");
  }

  async function pushCloud(nextEnvelope: VaultEnvelope, expectedRevision: number) {
    if (!userId) return;
    setSyncState("saving");
    try {
      const response = await apiRequest<CloudVaultResponse>(getToken, "/vault", {
        method: "PUT",
        body: JSON.stringify({
          expectedRevision,
          envelope: nextEnvelope,
          ...(historyResetPending.current ? { resetHistory: true } : {}),
        }),
      });
      historyResetPending.current = false;
      const revision = response.vault?.revision ?? expectedRevision;
      setCloudRevision(revision);
      await saveLocalVault(userId, { envelope: nextEnvelope, cloudRevision: revision });
      setSyncState("synced");
      setError("");
    } catch (nextError) {
      const message = nextError instanceof Error ? nextError.message : "Cloud backup failed";
      setSyncState(message.includes("revision") ? "conflict" : "offline");
      setError(`${message}. Your encrypted changes are still saved on this device.`);
    }
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!userId) return;
    const form = event.currentTarget;
    setError("");
    const data = new FormData(form);
    const passphrase = String(data.get("passphrase") ?? "");
    if (passphrase !== String(data.get("confirmation") ?? "")) {
      setError("The passphrases do not match");
      return;
    }
    setBusy(true);
    try {
      const created = await createVault(passphrase);
      await saveLocalVault(userId, { envelope: created.envelope, cloudRevision: 0 });
      setEnvelope(created.envelope);
      setPayload(created.payload);
      setVaultKey(created.vaultKey);
      setRecoveryKey(created.recoveryKey);
      setPhase("recovery");
      void pushCloud(created.envelope, 0);
      form.reset();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Could not create the vault");
    } finally {
      setBusy(false);
    }
  }

  async function unlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!envelope) return;
    const form = event.currentTarget;
    setError("");
    setBusy(true);
    try {
      const data = new FormData(form);
      const unlocked = await unlockVault(envelope, String(data.get("passphrase") ?? ""));
      setPayload(unlocked.payload);
      setVaultKey(unlocked.vaultKey);
      setPhase("unlocked");
      form.reset();
    } catch {
      setError("That passphrase cannot unlock this vault");
    } finally {
      setBusy(false);
    }
  }

  async function recover(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!envelope || !userId) return;
    const form = event.currentTarget;
    setError("");
    setBusy(true);
    try {
      const data = new FormData(form);
      const newPassphrase = String(data.get("newPassphrase") ?? "");
      if (newPassphrase !== String(data.get("confirmation") ?? "")) {
        throw new Error("The new passphrases do not match");
      }
      const recovered = await recoverVault(envelope, String(data.get("recoveryKey") ?? ""));
      // A used recovery key may be exposed: the vault gets a new data key and recovery key.
      const rekeyed = await rekeyVault(recovered, newPassphrase).finally(() => destroyVaultKey(recovered.vaultKey));
      historyResetPending.current = true;
      await saveLocalVault(userId, { envelope: rekeyed.envelope, cloudRevision, resetHistoryPending: true });
      setEnvelope(rekeyed.envelope);
      setPayload(rekeyed.payload);
      setVaultKey(rekeyed.vaultKey);
      setRecoveryKey(rekeyed.recoveryKey);
      setRecoverySaved(false);
      setRecoveryReplaced(true);
      setPhase("recovery");
      void pushCloud(rekeyed.envelope, cloudRevision);
      form.reset();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Recovery failed");
    } finally {
      setBusy(false);
    }
  }

  async function persistItems(items: VaultItem[], nextEnvironments = vaultEnvironments) {
    if (!envelope || !vaultKey || !payload || !userId) return;
    if (mutation.current || syncState === "saving") throw new Error("Wait for the current save to finish");
    const generation = session.current;
    mutation.current = true;
    try {
      const nextPayload: VaultPayload = { version: 2, sequence: payload.sequence + 1, items, environments: nextEnvironments };
      const nextEnvelope = await encryptVaultPayload(envelope, vaultKey, nextPayload);
      if (generation !== session.current) throw new Error("Vault locked; save cancelled");
      await saveLocalVault(userId, { envelope: nextEnvelope, cloudRevision, resetHistoryPending: historyResetPending.current });
      if (generation === session.current) setPayload(nextPayload);
      setEnvelope(nextEnvelope);
      await pushCloud(nextEnvelope, cloudRevision);
    } finally { mutation.current = false; }
  }

  async function saveItem(item: VaultItem) {
    const items = payload?.items ?? [];
    const next = items.some((candidate) => candidate.id === item.id)
      ? items.map((candidate) => (candidate.id === item.id ? item : candidate))
      : [...items, item];
    await persistItems(next);
  }

  async function deleteItem(item: VaultItem) {
    if (!window.confirm(`Delete ${item.service} / ${item.label}?`)) return;
    await persistItems((payload?.items ?? []).filter((candidate) => candidate.id !== item.id));
  }

  function reveal(itemId: string) {
    setRevealed((current) => new Set(current).add(itemId));
    window.setTimeout(
      () => setRevealed((current) => new Set([...current].filter((id) => id !== itemId))),
      15_000,
    );
  }

  async function copySecret(item: VaultItem) {
    await navigator.clipboard.writeText(item.secret);
    setCopiedId(item.id);
    window.setTimeout(() => setCopiedId((current) => (current === item.id ? null : current)), 1800);
    window.setTimeout(async () => {
      try {
        if ((await navigator.clipboard.readText()) === item.secret) await navigator.clipboard.writeText("");
      } catch {
        // Clipboard read permission is browser-dependent. The original value is never logged.
      }
    }, 30_000);
  }

  async function downloadAttachment(file: VaultAttachment) {
    const generation = session.current;
    try {
      const bytes = await readVaultAttachment(file);
      try {
        if (generation !== session.current) return;
        const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" }));
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = file.name;
        anchor.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      } finally { bytes.fill(0); }
    } catch { setError("Could not download this file"); }
  }

  function exportVault() {
    if (!envelope) return;
    downloadText(
      `vaultroom-keys-${new Date().toISOString().slice(0, 10)}.vaultroom`,
      JSON.stringify(envelope),
      "application/vnd.vaultroom.keys+json",
    );
  }

  async function importVault(file: File) {
    if (!userId) return;
    setError("");
    try {
      if (file.size > MAX_ENVELOPE_BYTES) throw new Error("Backup is too large");
      session.current++;
      const imported = await validateVaultEnvelope(JSON.parse(await file.text()));
      await saveLocalVault(userId, { envelope: imported, cloudRevision, resetHistoryPending: historyResetPending.current });
      if (vaultKey) await destroyVaultKey(vaultKey);
      setEditor(null);
      setManageEnvironments(false);
      setEnvelope(imported);
      setVaultKey(null);
      setPayload(null);
      setPhase("locked");
    } catch {
      setError("This file is not a readable Vaultroom backup");
    }
  }

  if (phase === "loading") {
    return <main className="keysGate keysLoading"><div className="keysLoader" aria-hidden="true"><i /><Fingerprint /><span /></div><p>Reading encrypted storage</p><small>LOCAL CIPHERTEXT · CLOUD REVISION</small></main>;
  }

  if (phase === "setup") {
    return <SetupScreen busy={busy} error={error} onCreate={create} onImport={() => importRef.current?.click()} importRef={importRef} onFile={importVault} />;
  }

  if (phase === "recovery") {
    return (
      <main className="keysGate recoveryGate">
        <section className="recoveryCard">
          <p className="keysKicker">ONE-TIME RECOVERY KIT</p>
          <h1>Save this outside your Mac.</h1>
          <p>This key can recover the vault if you forget the master passphrase. We cannot regenerate it.</p>
          {recoveryReplaced && <p>Your old passphrase and recovery key no longer open this vault. Backups exported before now still open with them.</p>}
          <code>{recoveryKey}</code>
          <div className="recoveryActions">
            <button onClick={() => void navigator.clipboard.writeText(recoveryKey)}><Clipboard /> Copy</button>
            <button onClick={() => downloadText("vaultroom-recovery-key.txt", recoveryKey)}><Download /> Download</button>
          </div>
          <label className="recoveryCheck"><input type="checkbox" checked={recoverySaved} onChange={(event) => setRecoverySaved(event.target.checked)} /> I stored the recovery key somewhere separate</label>
          <button className="keysPrimary" disabled={!recoverySaved} onClick={() => { setRecoveryKey(""); setRecoveryReplaced(false); setPhase("unlocked"); }}><ShieldCheck /> Enter my vault</button>
        </section>
      </main>
    );
  }

  if (phase === "locked") {
    return <LockedScreen envelope={envelope!} busy={busy} error={error} onUnlock={unlock} onRecover={recover} onImport={() => importRef.current?.click()} importRef={importRef} onFile={importVault} />;
  }

  return (
    <main className="keysApp" data-sync={syncState} data-rail-compact={railCompact}>
      <div className="keysAmbient" aria-hidden="true"><i /><i /><span>01001011</span><span>AEAD</span></div>
      <aside className="keysRail" data-compact={railCompact}>
        <div className="keysBrand"><KeyRound /> <span>VAULTROOM<br />KEYS</span></div>
        <button
          className="keysRailToggle"
          aria-label={railCompact ? "Expand sidebar" : "Collapse sidebar"}
          title={railCompact ? "Expand sidebar" : "Collapse sidebar"}
          onClick={() => setRailCompact((current) => {
            window.localStorage.setItem("vaultroom-rail-compact", String(!current));
            return !current;
          })}
        >
          {railCompact ? <PanelLeftOpen /> : <PanelLeftClose />}
        </button>
        <div className="keysStatus"><i /><span><strong>UNLOCKED</strong><small>Plaintext is in memory</small></span></div>
        <nav>
          <button data-active={filter === "all"} onClick={() => setFilter("all")} title="All secrets"><FileKey2 /><span className="railLabelText">All secrets</span><span className="railCount">{payload?.items.length ?? 0}</span></button>
          {vaultEnvironments.map((environment) => <button key={environment} data-active={filter === environment} onClick={() => setFilter(environment)} title={environment}><span className={`envDot ${environment}`} /><span className="railLabelText">{environment}</span><span className="railCount">{payload?.items.filter((item) => item.environment === environment).length ?? 0}</span></button>)}
          <button onClick={() => setManageEnvironments(true)} title="Manage environments"><Plus /><span className="railLabelText">Manage environments</span></button>
        </nav>
        <section className="keysSafety" data-state={syncState} aria-live="polite">{syncState === "saving" ? <LoaderCircle className="syncSpinner" /> : syncState === "offline" || syncState === "conflict" ? <CloudOff /> : <ShieldCheck />}<p><strong>{syncState === "synced" ? "Encrypted backup current" : syncState === "saving" ? "Uploading ciphertext" : syncState === "conflict" ? "Sync conflict" : syncState === "offline" ? "Cloud unavailable" : "Saved on this device"}</strong><small>Sequence {payload?.sequence ?? 0} · cloud rev {cloudRevision}</small></p></section>
        <SecurityExplainer placement="rail" />
        <footer><UserButton /><button onClick={() => void lock()} title="Lock vault"><Lock /><span>Lock vault</span></button></footer>
      </aside>

      <section className="keysWorkspace">
        <header className="keysTopbar">
          <label><Search /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search services, labels, notes" /></label>
          <div><button onClick={exportVault}><Download /> Export backup</button><button onClick={() => importRef.current?.click()}><Upload /> Import</button><button className="keysAdd" onClick={() => setEditor("new")}><Plus /> Add secret</button></div>
          <input ref={importRef} hidden type="file" accept=".vaultroom,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importVault(file); event.target.value = ""; }} />
        </header>

        <div className="keysHero"><button className="keysMobileEnvironments" onClick={() => setManageEnvironments(true)}>Manage environments</button><p className="keysKicker">LOCAL DECRYPTED VIEW</p><section className="keysHeroTitle"><h1>Secrets</h1><small>{filter === "all" ? "ALL ENVIRONMENTS" : filter.toUpperCase()}</small></section></div>

        <div className="keysList">
          <header><span>Service / label</span><span>Environment</span><span>Expiry</span><span>Secret</span><span /></header>
          {visibleItems.map((item, index) => (
            <article key={item.id} style={{ animationDelay: `${Math.min(index, 10) * 35}ms` }}>
              <span className="keyIdentity"><i>{item.service.slice(0, 2).toUpperCase()}</i><span><strong>{item.service}</strong><small>{item.label}</small></span></span>
              <span><b className={`envBadge ${item.environment}`}>{item.environment}</b></span>
              <span className={item.expiresAt && new Date(item.expiresAt) < new Date() ? "expired" : ""}><Clock3 /> {formatDate(item.expiresAt)}</span>
              <span className="secretCell" data-copied={copiedId === item.id}>{item.attachment ? <button className="keyFileDownload" onClick={() => void downloadAttachment(item.attachment!)} aria-label={`Download ${item.attachment.name}`}><Download /><span>{item.attachment.name}</span></button> : <><code>{revealed.has(item.id) ? item.secret : "••••••••••••••••••••"}</code><button aria-label={revealed.has(item.id) ? `Hide ${item.service} secret` : `Reveal ${item.service} secret`} onClick={() => revealed.has(item.id) ? setRevealed((current) => new Set([...current].filter((id) => id !== item.id))) : reveal(item.id)}>{revealed.has(item.id) ? <EyeOff /> : <Eye />}</button><button aria-label={`Copy ${item.service} secret`} onClick={() => void copySecret(item)}>{copiedId === item.id ? <Check /> : <Clipboard />}</button></>}</span>
              <button className="keyMore" aria-label={`Edit ${item.service}`} onClick={() => setEditor(item)}><MoreHorizontal /></button>
            </article>
          ))}
          {!visibleItems.length && <section className="keysEmpty"><KeyRound /><h2>{payload?.items.length ? "No matching secrets." : "The vault is empty."}</h2><p>{payload?.items.length ? "Change the search or environment filter." : "Add your first API key. It will be encrypted before it leaves memory."}</p><button onClick={() => setEditor("new")}><Plus /> Add first secret</button></section>}
        </div>
        {error && <div className="keysError">{error}</div>}
        {copiedId && <div className="keysToast" role="status"><Check /> Copied. Clipboard clears in 30 seconds.</div>}
      </section>

      {manageEnvironments && <EnvironmentEditor environments={vaultEnvironments} items={payload?.items ?? []} onClose={() => setManageEnvironments(false)} onSave={async (names, items) => { await persistItems(items, names); setFilter("all"); }} />}
      {editor && <ItemEditor environments={vaultEnvironments} item={editor === "new" ? null : editor} onClose={() => setEditor(null)} onSave={saveItem} onDelete={deleteItem} />}
    </main>
  );
}

function SetupScreen({ busy, error, onCreate, onImport, importRef, onFile }: { busy: boolean; error: string; onCreate: (event: FormEvent<HTMLFormElement>) => void; onImport: () => void; importRef: React.RefObject<HTMLInputElement | null>; onFile: (file: File) => Promise<void> }) {
  return <main className="keysGate setupGate"><header className="gateBrand"><KeyRound /> VAULTROOM KEYS</header><section><p className="keysKicker">NEW ENCRYPTED VAULT</p><h1>Make losing<br />your Mac boring.</h1><p>Your passphrase never leaves this device. There is no reset button, so you will also receive a separate recovery key.</p><form onSubmit={onCreate}><label>Master passphrase<input name="passphrase" type="password" minLength={12} required autoComplete="new-password" placeholder="At least 12 characters" /></label><label>Repeat passphrase<input name="confirmation" type="password" minLength={12} required autoComplete="new-password" /></label>{error && <small>{error}</small>}<button className="keysPrimary" disabled={busy}><Fingerprint /> {busy ? "Deriving encryption key…" : "Create encrypted vault"}</button></form><div className="gateDivider"><span>OR RESTORE</span></div><button className="gateImport" onClick={onImport}><Upload /> Import encrypted backup</button><input ref={importRef} hidden type="file" accept=".vaultroom,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void onFile(file); }} /></section><footer>ARGON2ID · XCHACHA20-POLY1305 · LOCAL-FIRST</footer></main>;
}

function LockedScreen({ envelope, busy, error, onUnlock, onRecover, onImport, importRef, onFile }: { envelope: VaultEnvelope; busy: boolean; error: string; onUnlock: (event: FormEvent<HTMLFormElement>) => void; onRecover: (event: FormEvent<HTMLFormElement>) => void; onImport: () => void; importRef: React.RefObject<HTMLInputElement | null>; onFile: (file: File) => Promise<void> }) {
  const [recoveryMode, setRecoveryMode] = useState(false);
  return <main className="keysGate lockedGate"><header className="gateBrand"><KeyRound /> VAULTROOM KEYS</header><section className="lockCard"><div className="lockGlyph"><Lock /></div><p className="keysKicker">VAULT LOCKED</p><h1>{recoveryMode ? "Recover access." : "Nothing readable here."}</h1><p>Encrypted on {formatDate(envelope.createdAt)}. Last changed {formatDate(envelope.updatedAt)}.</p>{!recoveryMode ? <form onSubmit={onUnlock}><label>Master passphrase<input name="passphrase" type="password" required autoFocus autoComplete="current-password" /></label>{error && <small>{error}</small>}<button className="keysPrimary" disabled={busy}><Fingerprint /> {busy ? "Checking encrypted vault…" : "Unlock on this device"}</button></form> : <form onSubmit={onRecover}><label>Recovery key<textarea name="recoveryKey" required autoFocus /></label><label>New master passphrase<input name="newPassphrase" type="password" required minLength={12} /></label><label>Repeat passphrase<input name="confirmation" type="password" required minLength={12} /></label>{error && <small>{error}</small>}<button className="keysPrimary" disabled={busy}><ShieldCheck /> Recover and rewrap key</button></form>}<div className="lockedLinks"><button onClick={() => setRecoveryMode(!recoveryMode)}>{recoveryMode ? "Use master passphrase" : "Use recovery key"}</button><button onClick={onImport}>Replace with backup</button></div><input ref={importRef} hidden type="file" accept=".vaultroom,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void onFile(file); }} /></section><footer>SERVER-SIDE PASSWORD RESET DOES NOT EXIST</footer></main>;
}

function ItemEditor({ item, onClose, onSave, onDelete, environments }: { environments: string[]; item: VaultItem | null; onClose: () => void; onSave: (item: VaultItem) => Promise<void>; onDelete: (item: VaultItem) => Promise<void> }) {
  const [saving, setSaving] = useState(false);
  const [closing, setClosing] = useState(false);
  const [error, setError] = useState("");
  const [attachment, setAttachment] = useState(item?.attachment);
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);

  async function selectFile(file?: File) {
    if (!file) return;
    setError("");
    if (file.size > MAX_FILE_BYTES) { setError("File exceeds 5 MiB"); return; }
    setSaving(true);
    let bytes: Uint8Array | undefined;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
      const next = await createVaultAttachment(file.name, bytes);
      if (active.current) setAttachment(next);
    } catch { if (active.current) setError("Could not read this file"); }
    finally { bytes?.fill(0); if (active.current) setSaving(false); }
  }

  function requestClose() {
    if (closing || saving) return;
    setClosing(true);
    window.setTimeout(onClose, 150);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (saving) return;
    setSaving(true);
    const data = new FormData(event.currentTarget);
    const now = new Date().toISOString();
    try {
    await onSave({ attachment, id: item?.id ?? crypto.randomUUID(), service: String(data.get("service")), label: String(data.get("label")), environment: String(data.get("environment")) as VaultEnvironment, secret: attachment ? "" : String(data.get("secret") ?? ""), notes: String(data.get("notes")), expiresAt: String(data.get("expiresAt") || "") || null, createdAt: item?.createdAt ?? now, updatedAt: now });
    onClose();
    } catch (error) { setError(error instanceof Error ? error.message : "Save failed"); }
    finally { setSaving(false); }
  }
  async function remove() {
    if (!item) return;
    setSaving(true);
    try { await onDelete(item); onClose(); }
    catch (error) { setError(error instanceof Error ? error.message : "Delete failed"); }
    finally { setSaving(false); }
  }

  return <div className="keyModalBackdrop" data-closing={closing} onMouseDown={requestClose}><form className="keyModal" onSubmit={submit} onMouseDown={(event) => event.stopPropagation()}><button type="button" className="keyModalClose" aria-label="Close secret editor" onClick={requestClose}><X /></button><p className="keysKicker">{item ? "EDIT SECRET" : "NEW SECRET"}</p><h2>{item ? item.service : "Add a key."}</h2><div className="keyFormGrid"><label>Service<input name="service" defaultValue={item?.service} required autoFocus placeholder="OpenRouter" /></label><label>Label<input name="label" defaultValue={item?.label} required placeholder="Personal account" /></label><label>Environment<select name="environment" defaultValue={item?.environment ?? environments[0]}>{environments.map((environment) => <option key={environment}>{environment}</option>)}</select></label><label>Expires<input name="expiresAt" type="date" defaultValue={item?.expiresAt?.slice(0, 10)} /></label><label className="keyFormFull">File (up to 5 MiB; 10 MiB total)<input type="file" disabled={saving} onChange={(event) => { void selectFile(event.target.files?.[0]); event.target.value = ""; }} /></label>{attachment ? <div className="keyFormFull"><p>{attachment.name} · {attachment.size.toLocaleString()} bytes</p><p>Encrypted with your vault. Downloads create an unencrypted copy on your device.</p><button type="button" disabled={saving} onClick={() => setAttachment(undefined)}>Remove file</button></div> : <label className="keyFormFull">Secret value<textarea name="secret" defaultValue={item?.secret} required spellCheck={false} /></label>}<label className="keyFormFull">Notes<textarea name="notes" defaultValue={item?.notes} /></label></div>{error && <p role="alert">{error}</p>}<footer>{item ? <button type="button" className="keyDelete" disabled={saving} onClick={() => void remove()}><Trash2 /> Delete</button> : <span />}<div><button type="button" onClick={requestClose}>Cancel</button><button className="keysPrimary" disabled={saving}><ShieldCheck /> {saving ? "Encrypting…" : "Encrypt and save"}</button></div></footer></form></div>;
}

function EnvironmentEditor({ environments, items, onSave, onClose }: {
  environments: string[]; items: VaultItem[];
  onSave: (names: string[], items: VaultItem[]) => Promise<void>; onClose: () => void;
}) {
  const [selected, setSelected] = useState(environments[0]);
  const [name, setName] = useState("");
  const [destination, setDestination] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  async function change(action: "add" | "rename" | "delete") {
    setError("");
    const nextName = name.trim();
    if (action !== "delete" && (!nextName || nextName === "all" || nextName.length > 60 || environments.includes(nextName))) {
      setError("Use a unique name of 1–60 characters (other than ‘all’)."); return;
    }
    if (action === "add" && environments.length >= 50) { setError("Maximum 50 environments."); return; }
    if (action === "delete" && environments.length === 1) { setError("Keep at least one environment."); return; }
    if (action === "delete" && items.some((item) => item.environment === selected) && (!destination || destination === selected)) {
      setError("Choose where to move the existing secrets first."); return;
    }
    const names = action === "add" ? [...environments, nextName] : action === "rename" ? environments.map((value) => value === selected ? nextName : value) : environments.filter((value) => value !== selected);
    const nextItems = action === "add" ? items : items.map((item) => item.environment === selected ? { ...item, environment: action === "rename" ? nextName : destination, updatedAt: new Date().toISOString() } : item);
    setSaving(true);
    try { await onSave(names, nextItems); onClose(); }
    catch (error) { setError(error instanceof Error ? error.message : "Could not save environments"); }
    finally { setSaving(false); }
  }
  return <div className="keyModalBackdrop"><section className="keyModal" role="dialog" aria-modal="true" aria-labelledby="environment-title">
    <button type="button" className="keyModalClose" disabled={saving} onClick={onClose} aria-label="Close environments"><X /></button>
    <p className="keysKicker">ENCRYPTED VAULT SETTINGS</p><h2 id="environment-title">Environments</h2>
    <div className="keyFormGrid"><label className="keyFormFull">Existing environment<select value={selected} onChange={(event) => { setSelected(event.target.value); setDestination(""); }}>{environments.map((value) => <option key={value}>{value}</option>)}</select></label>
    <label className="keyFormFull">New name<input value={name} onChange={(event) => setName(event.target.value)} maxLength={60} placeholder="e.g. Work" /></label>
    <label className="keyFormFull">Move secrets here when deleting<select value={destination} onChange={(event) => setDestination(event.target.value)}><option value="">Choose environment</option>{environments.filter((value) => value !== selected).map((value) => <option key={value}>{value}</option>)}</select></label></div>
    <p>Deleting an environment keeps its secrets and files. Names are encrypted with your vault.</p>
    {error && <p role="alert">{error}</p>}
    <footer><button className="keyDelete" disabled={saving} onClick={() => void change("delete")}><Trash2 /> Delete</button><div><button disabled={saving} onClick={() => void change("rename")}>Rename</button><button className="keysPrimary" disabled={saving} onClick={() => void change("add")}><Plus /> Add environment</button></div></footer>
  </section></div>;
}
