"use client";

import { ask } from "@/lib/ai";

export default function Chat() {
  return <button onClick={() => ask("hi")}>Ask</button>;
}
