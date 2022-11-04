import { createCookieSessionStorage, redirect } from "@remix-run/node";
import bcrypt from "bcryptjs";
import { db } from "./db.server";

export const login = async ({
  username,
  password,
}: {
  username: string;
  password: string;
}) => {
  const user = await db.user.findUnique({ where: { username } });

  if (!user) return null;

  const passwordValid = await bcrypt.compare(password, user.passwordHash);

  if (!passwordValid) return null;

  return { id: user.id, username };
};

const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) throw new Error("Session secret is required");

const storage = createCookieSessionStorage({
  cookie: {
    name: "Jokes_session",
    secure: process.env.NODE_ENV === "production",
    secrets: [sessionSecret],
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: true,
  },
});

export const createUserSession = async (userId: string, redirectTo: string) => {
  const session = await storage.getSession();
  session.set("userId", userId);
  return redirect(redirectTo, {
    headers: { "Set-Cookie": await storage.commitSession(session) },
  });
};

export const getUserSession = (request: Request) => {
  return storage.getSession(request.headers.get("Cookie"));
};

export const getUserId = async (request: Request) => {
  const session = await getUserSession(request);
  const userId = session.get("userId");

  if (!userId || typeof userId !== "string") return null;
  return userId;
};

export const requireUserId = async (
  request: Request,
  redirectTo: string = new URL(request.url).pathname
) => {
  const userId = await getUserId(request);

  if (!userId || typeof userId !== "string") {
    const searchParams = new URLSearchParams([["redirectTo", redirectTo]]);

    throw redirect(`/login?${searchParams}`);
  }

  return userId;
};

export async function getUser(request: Request) {
  const userId = await getUserId(request);
  if (!userId || typeof userId !== "string") {
    return null;
  }

  try {
    const user = await db.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true },
    });
    return user;
  } catch {
    throw logout(request);
  }
}

export const logout = async (request: Request) => {
  const session = await getUserSession(request);

  return redirect("/login", {
    headers: { "Set-Cookie": await storage.destroySession(session) },
  });
};

export const register = async (username: string, password: string) => {
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await db.user.create({ data: { username, passwordHash } });
  return { id: user.id, username };
};
