"use client";

import {
  AlertTriangle,
  ArrowRight,
  Cloud,
  Database,
  EyeOff,
  Fingerprint,
  KeyRound,
  ShieldQuestion,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export function SecurityExplainer({ placement = "landing" }: { placement?: "landing" | "rail" }) {
  const [open, setOpen] = useState(false);
  const [closing, setClosing] = useState(false);
  const closeTimer = useRef<number | null>(null);

  const close = useCallback(() => {
    if (closing) return;
    setClosing(true);
    closeTimer.current = window.setTimeout(() => {
      setOpen(false);
      setClosing(false);
    }, 150);
  }, [closing]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    document.body.dataset.modalOpen = "true";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      delete document.body.dataset.modalOpen;
      window.removeEventListener("keydown", onKeyDown);
      if (closeTimer.current) window.clearTimeout(closeTimer.current);
    };
  }, [close, open]);

  return (
    <>
      <button className={`securityExplainTrigger ${placement}`} onClick={() => setOpen(true)}>
        <ShieldQuestion />
        <span>{placement === "rail" ? "How encryption works" : "Why it is safe"}</span>
      </button>

      {open && createPortal(
        <div
          className="securityModalBackdrop"
          data-closing={closing}
          onMouseDown={close}
        >
          <section
            className="securityModal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="security-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <button className="securityModalClose" onClick={close} aria-label="Close explanation">
              <X />
            </button>

            <header>
              <p className="keysKicker">ZERO-KNOWLEDGE, IN PLAIN ENGLISH</p>
              <h2 id="security-title">The server gets<br />a locked box.</h2>
              <p>Your browser does the sensitive work. Railway only stores the result after encryption.</p>
            </header>

            <div className="securityFlow" aria-label="Vault encryption flow">
              <article className="localStep">
                <i><Fingerprint /></i>
                <small>01 · YOUR DEVICE</small>
                <strong>Master passphrase</strong>
                <p>You type it here. The app never sends it to our API.</p>
              </article>
              <div className="securityFlowArrow" aria-hidden="true"><ArrowRight /></div>
              <article className="localStep">
                <i><KeyRound /></i>
                <small>02 · YOUR DEVICE</small>
                <strong>Unlock and encrypt</strong>
                <p>Argon2id unlocks a random vault key. XChaCha encrypts the whole vault.</p>
              </article>
              <div className="securityFlowArrow" aria-hidden="true"><ArrowRight /></div>
              <article className="remoteStep">
                <i><Cloud /></i>
                <small>03 · ENCRYPTED TRANSIT</small>
                <strong>Ciphertext only</strong>
                <p>The network request contains a nonce, salt, version and unreadable ciphertext.</p>
              </article>
              <div className="securityFlowArrow" aria-hidden="true"><ArrowRight /></div>
              <article className="remoteStep">
                <i><Database /></i>
                <small>04 · RAILWAY</small>
                <strong>Backup the box</strong>
                <p>PostgreSQL keeps encrypted revisions. A new device decrypts them locally.</p>
              </article>
            </div>

            <div className="securityVisibility">
              <section>
                <span><Database /> The server can see</span>
                <ul>
                  <li>your account ID</li>
                  <li>encrypted blob size</li>
                  <li>revision and update time</li>
                </ul>
              </section>
              <section>
                <span><EyeOff /> The server cannot see</span>
                <ul>
                  <li>secret values or notes</li>
                  <li>service names or environments</li>
                  <li>master passphrase or recovery key</li>
                </ul>
              </section>
            </div>

            <footer>
              <AlertTriangle />
              <p><strong>The honest limit.</strong> This protects a database leak and a stolen encrypted backup. It cannot protect an already unlocked device, malware, or a malicious future web build. Keep a separate encrypted export for critical credentials until the product has an independent security review.</p>
            </footer>
          </section>
        </div>,
        document.body,
      )}
    </>
  );
}
