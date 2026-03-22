"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  fetchWithAuth,
  listProjects,
  createProject,
  listKeys,
  createKey,
  revokeKey,
  listEvents,
  archiveProject,
  ApiCallError,
  type ProjectResponse,
  type KeyResponse,
  type CreateKeyResponse,
  type EventResponse,
} from "@/lib/api";

// ── Main section ──────────────────────────────────────────────────────────────

export default function ProjectsSection() {
  const [projects, setProjects] = useState<ProjectResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const MAX_PROJECT_NAME = 80;
  const [selectedProject, setSelectedProject] = useState<ProjectResponse | null>(null);
  const [newKeyModal, setNewKeyModal] = useState<CreateKeyResponse | null>(null);

  const loadProjects = useCallback(() => {
    setLoading(true);
    fetchWithAuth((t) => listProjects(t))
      .then((ps) => setProjects(ps ?? []))
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load projects"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadProjects(); }, [loadProjects]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = newName.trim();
    if (!trimmed) return;
    if (trimmed.length > MAX_PROJECT_NAME) {
      setError(`Name must be at most ${MAX_PROJECT_NAME} characters`);
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const p = await fetchWithAuth((t) => createProject(t, trimmed));
      setProjects((prev) => [p, ...prev]);
      setNewName("");
    } catch (e) {
      setError(e instanceof ApiCallError ? e.message : "Failed to create project");
    } finally {
      setCreating(false);
    }
  }

  return (
    <section className="mt-8">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-base font-semibold text-zinc-100">Projects</h2>
      </div>

      {/* Create project form */}
      <form onSubmit={handleCreate} className="mb-4 flex gap-2">
        <input
          type="text"
          placeholder="Project name…"
          value={newName}
          onChange={(e) => { setNewName(e.target.value.slice(0, MAX_PROJECT_NAME)); setError(null); }}
          maxLength={MAX_PROJECT_NAME}
          className="flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
        />
        <button
          type="submit"
          disabled={creating || !newName.trim()}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-50"
        >
          {creating ? "Creating…" : "Create Project"}
        </button>
      </form>

      {error && (
        <p className="mb-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-400">
          {error}
        </p>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-sm text-zinc-500">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
          Loading…
        </div>
      )}

      {!loading && projects.length === 0 && (
        <p className="text-sm text-zinc-600">No projects yet. Create one above.</p>
      )}

      <div className="space-y-3">
        {projects.map((p) => (
          <ProjectRow
            key={p.id}
            project={p}
            selected={selectedProject?.id === p.id}
            onSelect={() =>
              setSelectedProject((prev) => (prev?.id === p.id ? null : p))
            }
            onKeyCreated={(k) => setNewKeyModal(k)}
            onArchived={() => {
              setProjects((prev) => prev.filter((x) => x.id !== p.id));
              if (selectedProject?.id === p.id) setSelectedProject(null);
            }}
          />
        ))}
      </div>

      {newKeyModal && (
        <NewKeyModal
          data={newKeyModal}
          onClose={() => setNewKeyModal(null)}
        />
      )}
    </section>
  );
}

// ── Project row with expandable key list ──────────────────────────────────────

function ProjectRow({
  project,
  selected,
  onSelect,
  onKeyCreated,
  onArchived,
}: {
  project: ProjectResponse;
  selected: boolean;
  onSelect: () => void;
  onKeyCreated: (k: CreateKeyResponse) => void;
  onArchived: () => void;
}) {
  const [keys, setKeys] = useState<KeyResponse[]>([]);
  const [keysLoading, setKeysLoading] = useState(false);
  const [creatingKey, setCreatingKey] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);

  useEffect(() => {
    if (!selected) return;
    setKeysLoading(true);
    fetchWithAuth((t) => listKeys(t, project.id))
      .then((ks) => setKeys(ks ?? []))
      .catch((e) => setKeyError(e instanceof Error ? e.message : "Failed to load keys"))
      .finally(() => setKeysLoading(false));
  }, [selected, project.id]);

  async function handleCreateKey(e: React.FormEvent) {
    e.preventDefault();
    if (!keyName.trim()) return;
    setCreatingKey(true);
    setKeyError(null);
    try {
      const created = await fetchWithAuth((t) => createKey(t, project.id, keyName.trim()));
      setKeys((prev) => [created, ...prev]);
      setKeyName("");
      onKeyCreated(created);
    } catch (e) {
      setKeyError(e instanceof ApiCallError ? e.message : "Failed to create key");
    } finally {
      setCreatingKey(false);
    }
  }

  async function handleRevoke(keyId: string) {
    try {
      await fetchWithAuth((t) => revokeKey(t, project.id, keyId));
      setKeys((prev) =>
        prev.map((k) =>
          k.id === keyId ? { ...k, revoked_at: new Date().toISOString() } : k,
        ),
      );
    } catch (e) {
      setKeyError(e instanceof ApiCallError ? e.message : "Failed to revoke key");
    }
  }

  async function handleArchive() {
    if (!confirm(`Archive project "${project.name}"? You won't see it in the list anymore.`)) return;
    try {
      await fetchWithAuth((t) => archiveProject(t, project.id));
      onArchived();
    } catch (e) {
      setKeyError(e instanceof ApiCallError ? e.message : "Failed to archive project");
    }
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900">
      {/* Header */}
      <div className="flex w-full items-center justify-between px-4 py-3">
        <Link
          href={`/projects/${project.id}`}
          onClick={(e) => e.stopPropagation()}
          className="flex-1 min-w-0"
        >
          <p className="font-medium text-zinc-100 hover:text-indigo-400 hover:underline">
            {project.name}
          </p>
          <p className="text-xs text-zinc-500">
            {project.created_at ? new Date(project.created_at).toLocaleString() : ""}
          </p>
        </Link>
        <button
          onClick={onSelect}
          className="shrink-0 p-1 -m-1 rounded hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300"
          aria-label={selected ? "Collapse" : "Expand"}
        >
          <ChevronIcon open={selected} />
        </button>
      </div>

      {/* Expanded key list */}
      {selected && (
        <div className="border-t border-zinc-800 px-4 pb-4 pt-3">
          {keyError && (
            <p className="mb-2 rounded border border-red-800 bg-red-950 px-3 py-1.5 text-xs text-red-400">
              {keyError}
            </p>
          )}

          {/* Create key form */}
          <form onSubmit={handleCreateKey} className="mb-3 flex gap-2">
            <input
              type="text"
              placeholder="Key name…"
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
              className="flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-100 placeholder-zinc-600 focus:border-indigo-500 focus:outline-none"
            />
            <button
              type="submit"
              disabled={creatingKey || !keyName.trim()}
              className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-50"
            >
              {creatingKey ? "…" : "Create API Key"}
            </button>
          </form>

          {keysLoading && (
            <p className="text-xs text-zinc-600">Loading keys…</p>
          )}

          {!keysLoading && keys.length === 0 && (
            <p className="text-xs text-zinc-600">No API keys yet.</p>
          )}

          <div className="space-y-2">
            {keys.map((k) => (
              <KeyRow key={k.id} apiKey={k} onRevoke={() => handleRevoke(k.id)} />
            ))}
          </div>

          <EventsSection projectId={project.id} />

          <div className="mt-4 border-t border-zinc-800 pt-3">
            <button
              onClick={handleArchive}
              className="rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 transition hover:border-red-700 hover:text-red-400"
            >
              Archive Project
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Key row ───────────────────────────────────────────────────────────────────

function KeyRow({
  apiKey,
  onRevoke,
}: {
  apiKey: KeyResponse;
  onRevoke: () => void;
}) {
  const revoked = !!apiKey.revoked_at;
  return (
    <div className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2">
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-zinc-200">{apiKey.name}</p>
        <p className="font-mono text-xs text-zinc-500">
          sk_live_…{apiKey.last4}
          {revoked && (
            <span className="ml-2 rounded bg-red-900/40 px-1.5 py-0.5 text-red-400">
              revoked
            </span>
          )}
        </p>
      </div>
      {!revoked && (
        <button
          onClick={onRevoke}
          className="ml-3 shrink-0 rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-400 transition hover:border-red-700 hover:text-red-400"
        >
          Revoke
        </button>
      )}
    </div>
  );
}

// ── Events section ────────────────────────────────────────────────────────────

function EventsSection({ projectId }: { projectId: string }) {
  const [events, setEvents] = useState<EventResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  async function handleLoad() {
    setLoading(true);
    setError(null);
    try {
      const evs = await fetchWithAuth((t) => listEvents(t, projectId));
      setEvents(evs ?? []);
      setLoaded(true);
    } catch (e) {
      setError(e instanceof ApiCallError ? e.message : "Failed to load events");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mt-3 border-t border-zinc-800 pt-3">
      <div className="mb-2 flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Events</p>
        <button
          onClick={handleLoad}
          disabled={loading}
          className="rounded border border-zinc-700 px-2 py-0.5 text-xs text-zinc-400 transition hover:border-zinc-500 hover:text-zinc-200 disabled:opacity-50"
        >
          {loading ? "Loading…" : "Load Events"}
        </button>
      </div>

      {error && (
        <p className="mb-2 rounded border border-red-800 bg-red-950 px-2 py-1 text-xs text-red-400">
          {error}
        </p>
      )}

      {loaded && events.length === 0 && (
        <p className="text-xs text-zinc-600">No events yet. Send one via POST /ingest.</p>
      )}

      {events.length > 0 && (
        <div className="space-y-1">
          {events.slice(0, 20).map((ev) => (
            <div key={ev.id} className="rounded-lg border border-zinc-800 bg-zinc-950">
              <button
                onClick={() => setExpanded((prev) => (prev === ev.id ? null : ev.id))}
                className="flex w-full items-center justify-between px-3 py-2 text-left"
              >
                <div className="min-w-0 flex-1">
                  <span className="font-mono text-xs font-semibold text-emerald-400">
                    {ev.event}
                  </span>
                  <span className="ml-3 text-xs text-zinc-500">
                    {new Date(ev.received_at).toLocaleString()}
                  </span>
                </div>
                <svg
                  className={`ml-2 h-3 w-3 shrink-0 text-zinc-600 transition-transform ${expanded === ev.id ? "rotate-180" : ""}`}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              {expanded === ev.id && (
                <pre className="overflow-x-auto border-t border-zinc-800 px-3 py-2 font-mono text-xs text-zinc-400">
                  {JSON.stringify(ev.payload, null, 2)}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── New key modal (shows plaintext once) ──────────────────────────────────────

function NewKeyModal({
  data,
  onClose,
}: {
  data: CreateKeyResponse;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(data.api_key).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
      <div className="w-full max-w-md rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
        <h3 className="mb-1 text-lg font-semibold">API Key Created</h3>
        <p className="mb-4 text-sm text-zinc-400">
          Copy this key now — it will <span className="font-semibold text-zinc-200">never be shown again</span>.
        </p>

        <div className="mb-4 flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2">
          <code className="flex-1 break-all font-mono text-xs text-emerald-400">
            {data.api_key}
          </code>
          <button
            onClick={handleCopy}
            className="shrink-0 rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-400 transition hover:border-zinc-500 hover:text-zinc-200"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>

        <div className="flex gap-2">
          <button
            onClick={onClose}
            className="flex-1 rounded-lg bg-indigo-600 py-2 text-sm font-semibold text-white transition hover:bg-indigo-500"
          >
            I've saved the key
          </button>
          <Link
            href={`/ingest-test?key=${encodeURIComponent(data.api_key)}`}
            onClick={onClose}
            className="flex items-center justify-center rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-400 transition hover:border-zinc-500 hover:text-zinc-200"
          >
            Test ingest →
          </Link>
        </div>
      </div>
    </div>
  );
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      className={`h-4 w-4 shrink-0 text-zinc-500 transition-transform ${open ? "rotate-180" : ""}`}
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      viewBox="0 0 24 24"
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  );
}
