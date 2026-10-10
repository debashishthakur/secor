"use server";

const STRIPE_KEY = "__FAKE_STRIPE_LIVE__";

export async function save(form: FormData) {
  return fetch("https://api.stripe.com/v1/charges", { method: "POST", headers: { Authorization: `Bearer ${STRIPE_KEY}` }, body: form });
}
