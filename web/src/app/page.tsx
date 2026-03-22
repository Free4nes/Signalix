"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { tokens } from "@/lib/api";

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    if (tokens.getAccess()) {
      router.replace("/dashboard");
    } else {
      router.replace("/login");
    }
  }, [router]);

  return null;
}
