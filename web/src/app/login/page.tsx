"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { requestOtp, ApiCallError } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [phone, setPhone] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await requestOtp(phone.trim());
      router.push(`/otp?phone=${encodeURIComponent(phone.trim())}`);
    } catch (err) {
      setError(err instanceof ApiCallError ? err.message : "Failed to send OTP");
    } finally {
      setLoading(false);
    }
  }

  return (
    <CenterLayout>
    <Card title="Sign in to Signalix">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-zinc-400 mb-1">
            Phone number
          </label>
          <input
            type="tel"
            placeholder="+491234567890"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            required
            className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2.5 text-zinc-100 placeholder-zinc-600 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>

        {error && <ErrorBanner message={error} />}

        <button
          type="submit"
          disabled={loading || phone.trim() === ""}
          className="w-full rounded-lg bg-indigo-600 px-4 py-2.5 font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "Sending…" : "Send OTP"}
        </button>
      </form>
    </Card>
    </CenterLayout>
  );
}

function CenterLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      {children}
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-8 shadow-xl">
      <h1 className="mb-6 text-center text-2xl font-bold tracking-tight">{title}</h1>
      {children}
    </div>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <p className="rounded-lg border border-red-800 bg-red-950 px-4 py-2 text-sm text-red-400">
      {message}
    </p>
  );
}
