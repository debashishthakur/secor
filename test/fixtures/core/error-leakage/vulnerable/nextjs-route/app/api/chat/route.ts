import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    return NextResponse.json({ ok: true, body });
  } catch (error) {
    return NextResponse.json({ error }, { status: 500 });
  }
}

export async function GET() {
  try {
    return Response.json(await load());
  } catch (e) {
    return Response.json({ message: `Failed: ${e}` }, { status: 500 });
  }
}
