"use server";
import { auth } from "@/auth";
export async function subscribe(email: string) { return email; }
export async function deletePost(id: string) { const s = await auth(); return s ? id : null; }
export function notAnAction() {}
export const helper = 1;
