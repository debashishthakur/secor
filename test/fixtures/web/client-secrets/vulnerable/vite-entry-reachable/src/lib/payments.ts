const STRIPE_SECRET = "__FAKE_STRIPE_LIVE__";
const STRIPE_TEST = "__FAKE_STRIPE_TEST__";

export function charge(amount: number) {
  return fetch("https://api.stripe.com/v1/charges", { method: "POST", headers: { Authorization: `Bearer ${amount > 0 ? STRIPE_SECRET : STRIPE_TEST}` } });
}
