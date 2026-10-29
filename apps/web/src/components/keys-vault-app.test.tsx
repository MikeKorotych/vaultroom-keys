import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KeysVaultApp } from "./keys-vault-app";

const mocks = vi.hoisted(() => ({
  getToken: vi.fn(), load: vi.fn(), save: vi.fn(), api: vi.fn(), unlock: vi.fn(), validate: vi.fn(),
}));
vi.mock("@clerk/nextjs", () => ({ useAuth: () => ({ userId: "fake-user", getToken: mocks.getToken }), UserButton: () => null }));
vi.mock("@/components/security-explainer", () => ({ SecurityExplainer: () => null }));
vi.mock("@/lib/api", () => ({ apiRequest: mocks.api }));
vi.mock("@/lib/vault-storage", () => ({ loadLocalVault: mocks.load, saveLocalVault: mocks.save }));
vi.mock("@vaultroom/crypto", () => ({
  MAX_FILE_BYTES: 5 * 1024 * 1024, MAX_ENVELOPE_BYTES: 20 * 1024 * 1024,
  destroyVaultKey: vi.fn(async () => {}), unlockVault: mocks.unlock,
  encryptVaultPayload: vi.fn(async (envelope, _key, payload) => ({ ...envelope, fixture: payload })),
  validateVaultEnvelope: mocks.validate,
}));

const initial = () => ({ createdAt: "2026-01-01", updatedAt: "2026-01-01", fixture: { version: 2, sequence: 0, items: [] as Array<Record<string, unknown>> } });
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
async function unlock() {
  fireEvent.change(screen.getByLabelText("Master passphrase"), { target: { value: "fake test passphrase" } });
  fireEvent.submit(screen.getByLabelText("Master passphrase").closest("form")!);
  await screen.findByRole("heading", { name: "Secrets" });
}
async function addSecret(service: string, environment?: string) {
  fireEvent.click(screen.getByRole("button", { name: "Add secret" }));
  fireEvent.change(screen.getByLabelText("Service"), { target: { value: service } });
  fireEvent.change(screen.getByLabelText("Label", { exact: true }), { target: { value: "Fake fixture" } });
  fireEvent.change(screen.getByLabelText("Secret value"), { target: { value: "not-a-real-key" } });
  if (environment) fireEvent.change(screen.getByLabelText("Environment", { exact: true }), { target: { value: environment } });
  fireEvent.submit(screen.getByLabelText("Service").closest("form")!);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.load.mockResolvedValue({ envelope: initial(), cloudRevision: 1 });
  mocks.save.mockResolvedValue(undefined);
  mocks.api.mockImplementation(async (_token, _path, request) => request ? { vault: { revision: 2 } } : { vault: null });
  mocks.unlock.mockImplementation(async (envelope) => ({ payload: envelope.fixture, vaultKey: new Uint8Array(32) }));
  mocks.validate.mockImplementation(async (envelope) => envelope);
});
afterEach(cleanup);

describe("vault operation serialization", () => {
  it("locks immediately but defers unlock until the committed edit is available", async () => {
    const pending = deferred();
    mocks.save.mockImplementationOnce(() => pending.promise);
    render(<KeysVaultApp />);
    await screen.findByLabelText("Master passphrase");
    await unlock();
    await addSecret("First edit");
    await waitFor(() => expect(mocks.save).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByTitle("Lock vault"));
    await screen.findByLabelText("Master passphrase");
    expect((screen.getByRole("button", { name: /Checking encrypted vault/ }) as HTMLButtonElement).disabled).toBe(true);
    // Even a programmatic submit cannot bypass the synchronous operation guard.
    fireEvent.submit(screen.getByLabelText("Master passphrase").closest("form")!);
    expect(mocks.unlock).toHaveBeenCalledTimes(1);
    await act(async () => { pending.resolve(); await pending.promise; });
    await screen.findByRole("button", { name: "Unlock on this device" });
    await unlock();
    expect(screen.getByText("First edit")).toBeTruthy();
    await addSecret("Second edit");
    await waitFor(() => expect(screen.queryByLabelText("Service")).toBeNull());
    const last = mocks.save.mock.calls.at(-1)![1];
    expect(last.envelope.fixture.items.map((item: { service: string }) => item.service)).toEqual(["First edit", "Second edit"]);
  });

  it.each(["local", "cloud"])("prevents import during a pending %s write and permits it after completion", async (stage) => {
    const pending = deferred();
    if (stage === "local") mocks.save.mockImplementationOnce(() => pending.promise);
    else mocks.api.mockImplementation(async (_token, _path, request) => {
      if (!request) return { vault: null };
      await pending.promise;
      return { vault: { revision: 2 } };
    });
    const { container } = render(<KeysVaultApp />);
    await screen.findByLabelText("Master passphrase");
    await unlock();
    await addSecret("Pending edit");
    await waitFor(() => expect(mocks.save).toHaveBeenCalledTimes(1));
    const backup = { ...initial(), marker: "imported-backup" };
    const file = { size: 100, text: async () => JSON.stringify(backup) };
    const input = container.querySelector('input[accept=".vaultroom,application/json"]')!;
    fireEvent.change(input, { target: { files: [file] } });
    expect(mocks.validate).not.toHaveBeenCalled();
    await act(async () => { pending.resolve(); await pending.promise; });
    await waitFor(() => expect(screen.queryByLabelText("Service")).toBeNull());
    fireEvent.change(input, { target: { files: [file] } });
    await screen.findByLabelText("Master passphrase");
    expect(mocks.save.mock.calls.at(-1)![1].envelope.marker).toBe("imported-backup");
  });

  it("does not interpret custom environment names as application classes", async () => {
    const envelope = initial();
    envelope.fixture.items.push({ id: "fake", service: "Fixture", label: "Label", secret: "fake", notes: "", environment: "keyModalBackdrop", expiresAt: null, updatedAt: "2026-01-01" });
    mocks.load.mockResolvedValue({ envelope: { ...envelope, fixture: { ...envelope.fixture, environments: ["keyModalBackdrop"] } }, cloudRevision: 1 });
    const { container } = render(<KeysVaultApp />);
    await screen.findByLabelText("Master passphrase");
    await unlock();
    expect(screen.getAllByText("keyModalBackdrop").length).toBe(2);
    expect(container.querySelector(".keyModalBackdrop")).toBeNull();
    expect(container.querySelector(".envBadge")?.className).toBe("envBadge ");
  });
  it("adds, renames and deletes an environment without deleting its secrets", async () => {
    render(<KeysVaultApp />);
    await screen.findByLabelText("Master passphrase");
    await unlock();
    fireEvent.click(screen.getByTitle("Manage environments"));
    fireEvent.change(screen.getByLabelText("New name"), { target: { value: "Work" } });
    fireEvent.click(screen.getByRole("button", { name: "Add environment" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await addSecret("Keep this secret", "Work");
    await waitFor(() => expect(screen.queryByLabelText("Service")).toBeNull());
    fireEvent.click(screen.getByTitle("Manage environments"));
    fireEvent.change(screen.getByLabelText("Existing environment"), { target: { value: "Work" } });
    fireEvent.change(screen.getByLabelText("New name"), { target: { value: "Office" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mocks.save.mock.calls.at(-1)![1].envelope.fixture.items[0].environment).toBe("Office");
    fireEvent.click(screen.getByTitle("Manage environments"));
    fireEvent.change(screen.getByLabelText("Existing environment"), { target: { value: "Office" } });
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(screen.getByRole("alert").textContent).toContain("Choose where to move");
    fireEvent.change(screen.getByLabelText("Move secrets here when deleting"), { target: { value: "personal" } });
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const payload = mocks.save.mock.calls.at(-1)![1].envelope.fixture;
    expect(payload.environments).not.toContain("Office");
    expect(payload.items).toHaveLength(1);
    expect(payload.items[0].environment).toBe("personal");
    expect(screen.getByText("Keep this secret")).toBeTruthy();
  });

});
