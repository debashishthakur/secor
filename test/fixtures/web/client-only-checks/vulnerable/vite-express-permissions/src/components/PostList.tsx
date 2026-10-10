import { removePost } from "../api";

export function PostList({ permissions, id }: { permissions: string[]; id: string }) {
  return (
    <ul>
      {permissions.includes("posts:delete") && <button onClick={() => removePost(id)}>Delete</button>}
    </ul>
  );
}
