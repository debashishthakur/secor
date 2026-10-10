export default function Form() {
  async function save(formData: FormData) {
    "use server";
    return formData.get("x");
  }
  return <form action={save}></form>;
}
