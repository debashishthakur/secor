"use client";

export function AdminTools({ isAdmin, id }: { isAdmin: boolean; id: string }) {
  async function purge() {
    await fetch(`/api/admin/users/${id}`, { method: "DELETE" });
  }
  if (!isAdmin) return null;
  return <button onClick={purge}>Purge</button>;
}
