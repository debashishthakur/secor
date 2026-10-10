import { initializeApp } from "./firebase";

export default function App() {
  initializeApp();
  return <p>{import.meta.env.VITE_SUPABASE_ANON_KEY ? "ok" : "no"}</p>;
}
