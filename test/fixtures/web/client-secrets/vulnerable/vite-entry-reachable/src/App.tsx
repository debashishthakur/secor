import { charge } from "./lib/payments";
import { MAP_KEY } from "./lib/maps";

export default function App() {
  return <button data-map={MAP_KEY} onClick={() => charge(100)}>Pay</button>;
}
