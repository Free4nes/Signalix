"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8080";

const DEFAULT_BODY = JSON.stringify({ event: "hello", data: { x: 1 } }, null, 2);

function IngestTestForm() {
  const params = useSearchParams();
  const [apiKey, setApiKey] = useState(params.get("key") ?? "");
  const [body, setBody] = useState(DEFAULT_BODY);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ status: number; body: string } | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    setParseError(null);
    setResult(null);

    try {
      JSON.parse(body);
    } catch {
      setParseError("Invalid JSON in body");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("http://localhost:8080/ingest", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey.trim(),
        },
        body,
      });
      const text = await res.text();
      let pretty = text;
      try {
        pretty = JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        // leave as-is if not JSON
      }
      setResult({ status: res.status, body: pretty });
    } catch (err) {
      setResult({ status: 0, body: err instanceof Error ? err.message : "Network error" });
    } finally {
      setLoading(false);
    }
  }

  const statusColor =
    result === null
      ? ""
      : result.status >= 200 && result.status < 300
        ? "text-emerald-400"
        : "text-red-400";

  return (
    <div className="min-h-screen bg-zinc-950 px-4 py-10 text-zinc-100">
      <div className="mx-auto max-w-xl">
        {/* Header */}
        <div className="mb-6 flex items-center gap-3">
          <Link
            href="/dashboard"
            className="text-sm text-zinc-500 transition hover:text-zinc-300"
          >
            ← Dashboard
          </Link>
          <span className="text-zinc-700">/</span>
          <h1 className="text-lg font-semibold">Ingest Test</h1>
        </div>

        <p className="mb-6 text-sm text-zinc-400">
          Send a test event to{" "}
          <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-300">
            POST /ingest
          </code>{" "}
          using an API key. The key is sent as{" "}
          <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-300">
            X-API-Key
          </code>
          .
        </p>

        <form onSubmit={handleSend} className="space-y-4">
          {/* API Key */}
          <div>
            <label className="mb-1 block text-sm font-medium text-zinc-400">
              API Key
            </label>
            <input
              type="text"
              placeholder="sk_live_…"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              required
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm text-zinc-100 placeholder-zinc-600 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>

          {/* JSON body */}
          <div>
            <label className="mb-1 block text-sm font-medium text-zinc-400">
              Request body (JSON)
            </label>
            <textarea
              rows={7}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              spellCheck={false}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm text-zinc-100 placeholder-zinc-600 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
            {parseError && (
              <p className="mt-1 text-xs text-red-400">{parseError}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || !apiKey.trim()}
            className="w-full rounded-lg bg-indigo-600 py-2.5 font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "Sending…" : "Send"}
          </button>
        </form>

        {/* Response */}
        {result && (
          <div className="mt-6 rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xs font-semibold uppercase tracking-widest text-zinc-500">
                Response
              </span>
              <span className={`font-mono text-sm font-bold ${statusColor}`}>
                {result.status === 0 ? "Error" : result.status}
              </span>
            </div>
            <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-zinc-300">
              {result.body}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

export default function IngestTestPage() {
  return (
    <Suspense>
      <IngestTestForm />
    </Suspense>
  );
}
