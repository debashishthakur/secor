import { PostList } from "./components/PostList";

export default function App() {
  return <PostList permissions={["posts:delete"]} id="1" />;
}
