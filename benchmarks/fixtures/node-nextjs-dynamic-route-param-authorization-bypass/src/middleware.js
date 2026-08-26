import { NextResponse } from "next/server";

export function middleware(request) {
  if (request.nextUrl.pathname === "/documents/secret") {
    return new NextResponse("Unauthorized", { status: 401 });
  }
  return NextResponse.next();
}

export const config = { matcher: "/documents/:path*" };
