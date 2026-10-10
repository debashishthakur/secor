import { pgTable, serial, text } from "drizzle-orm/pg-core";

export const accounts = pgTable("accounts", {
  id: serial("id").primaryKey(),
  email: text("email").notNull(),
  passwordHash: text("password_hash").notNull(),
});
