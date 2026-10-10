export function PostList({ isAdmin, id }: { isAdmin: boolean; id: string }) {
  const remove = () => fetch(`/api/posts/${id}`, { method: "DELETE" });
  return <ul>{isAdmin && <button onClick={remove}>Delete</button>}</ul>;
}
