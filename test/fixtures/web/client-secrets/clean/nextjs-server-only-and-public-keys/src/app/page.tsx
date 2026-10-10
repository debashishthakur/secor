import { load } from "@/lib/server-data";
import Form from "@/components/Form";

export default async function Page() {
  const data = await load();
  return <Form initial={data} />;
}
