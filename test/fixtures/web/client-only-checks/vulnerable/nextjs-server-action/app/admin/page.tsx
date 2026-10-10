import UserTable from "@/components/UserTable";

export default function Page() {
  return <UserTable user={{ role: "admin" }} id="1" />;
}
