export async function removePost(id: string) {
  return fetch("/api/posts/" + id, { method: "DELETE" });
}
