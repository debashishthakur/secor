import { NextResponse } from "next/server";

export async function POST() {
  try {
    return NextResponse.json(await handle());
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error: "Something went wrong" }, { status: 500 });
  }
}

export async function GET() {
  try {
    return Response.json(await load());
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Unknown error" }, { status: 500 });
  }
}
