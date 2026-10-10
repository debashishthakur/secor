const Stripe = require("stripe");

const stripe = Stripe("__FAKE_STRIPE_TEST__");
module.exports = { stripe };
