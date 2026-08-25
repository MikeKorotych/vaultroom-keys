import { Show, SignInButton } from "@clerk/nextjs";
import { KeyRound } from "lucide-react";
import { KeysVaultApp } from "@/components/keys-vault-app";
import { SecurityExplainer } from "@/components/security-explainer";
import { DotPlasmaBackground } from "@/components/dot-plasma-background";

export default function Home() {
  return (
    <>
      <DotPlasmaBackground />
      <Show when="signed-out">
        <main className="signInPage">
          <div className="signInMark"><KeyRound /> VAULTROOM KEYS / OPEN SOURCE BETA</div>
          <section>
            <p className="eyebrow">CLIENT-ENCRYPTED DEVELOPER VAULT</p>
            <h1><span>Your keys.</span><span>Unreadable to us.</span></h1>
            <p>Back up API keys and recovery codes. Encryption happens on this device before anything is stored.</p>
            <div className="signInActions">
              <SignInButton mode="modal"><button className="signInPrimary">Open private vault</button></SignInButton>
              <SecurityExplainer />
            </div>
          </section>
          <footer>ARGON2ID · XCHACHA20-POLY1305 · NO PASSWORD RESET</footer>
        </main>
      </Show>
      <Show when="signed-in"><KeysVaultApp /></Show>
    </>
  );
}
