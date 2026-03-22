"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { verifyOtp, tokens, ApiCallError } from "@/lib/api";

function OtpForm() {
  const router = useRouter();
  const params = useSearchParams();
  const phone = params.get("phone") ?? "";

  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await verifyOtp(phone, otp.trim());
      tokens.set(res.access_token, res.refresh_token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof ApiCallError ? err.message : "Invalid or expired OTP");
    } finally {
      setLoading(false);
    }
  }

  return (
    <CenterLayout>
    <Card title="Enter your OTP">
      <p className="mb-6 text-center text-sm text-zinc-400">
        Code sent to <span className="font-medium text-zinc-200">{phone || "your phone"}</span>
      </p>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-zinc-400 mb-1">
            One-time password
          </label>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            placeholder="123456"
            value={otp}
            onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
            required
            autoFocus
            className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2.5 text-center text-2xl tracking-[0.5em] text-zinc-100 placeholder-zinc-600 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>

        {error && <ErrorBanner message={error} />}

        <button
          type="submit"
          disabled={loading || otp.length < 6}
          className="w-full rounded-lg bg-indigo-600 px-4 py-2.5 font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "Verifying…" : "Verify"}
        </button>

        <button
          type="button"
          onClick={() => router.push("/login")}
          className="w-full text-sm text-zinc-500 hover:text-zinc-300 transition"
        >
          ← Back
        </button>
      </form>
    </Card>
    </CenterLayout>
  );
}

export default function OtpPage() {
  return (
    <Suspense>
      <OtpForm />
    </Suspense>
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
      <h1 className="mb-2 text-center text-2xl font-bold tracking-tight">{title}</h1>
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
