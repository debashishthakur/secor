"use client";

import { deleteUser } from "@/app/actions";

export default function UserTable({ user, id }: { user: { role: string }; id: string }) {
  return (
    <div>
      {user.role === "admin" && (
        <button onClick={() => deleteUser(id)}>Delete</button>
      )}
    </div>
  );
}
