"use client";

import { save } from "@/app/actions";
import { firebaseConfig } from "@/lib/firebase";

export default function Form({ initial }: { initial: number }) {
  return <form action={save}><input name="n" defaultValue={initial} data-project={firebaseConfig.projectId} /></form>;
}
