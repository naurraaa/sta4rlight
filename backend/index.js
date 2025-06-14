import { Router } from "itty-router";
const router = Router();

// Utility for basic auth (very simple)
async function isAuthenticated(req) {
  const auth = req.headers.get("Authorization");
  if (!auth || !auth.startsWith("Basic ")) return false;
  const decoded = atob(auth.replace("Basic ", ""));
  const [username, password] = decoded.split(":");
  return username === "admin" && password === "admin123";
}

// Auth middleware
const requireAuth = async (req) => {
  if (!(await isAuthenticated(req)))
    return new Response("Unauthorized", { status: 401 });
};

// Login endpoint
router.post("/api/login", async (req, env) => {
  const { username, password } = await req.json();
  const { results } = await env.DB.prepare(
    "SELECT * FROM users WHERE username = ? AND password = ?"
  )
    .bind(username, password)
    .all();
  if (results.length > 0) {
    return Response.json({ success: true });
  } else {
    return Response.json({ success: false }, { status: 401 });
  }
});

// Get all tickets
router.get("/api/tickets", async (req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM tickets").all();
  return Response.json(results);
});

// Create a new ticket
router.post("/api/tickets", async (req, env) => {
  const authRes = await requireAuth(req);
  if (authRes) return authRes;

  const data = await req.json();
  await env.DB.prepare(
    "INSERT INTO tickets (title, description, price, quota) VALUES (?, ?, ?, ?)"
  )
    .bind(data.title, data.description, data.price, data.quota)
    .run();
  return new Response("Created", { status: 201 });
});

// Update a ticket
router.put("/api/tickets/:id", async ({ params, json, request }, env) => {
  const authRes = await requireAuth(request);
  if (authRes) return authRes;

  const data = await json();
  await env.DB.prepare(
    "UPDATE tickets SET title = ?, description = ?, price = ?, quota = ? WHERE id = ?"
  )
    .bind(data.title, data.description, data.price, data.quota, params.id)
    .run();
  return new Response("Updated");
});

// Delete a ticket
router.delete("/api/tickets/:id", async ({ params, request }, env) => {
  const authRes = await requireAuth(request);
  if (authRes) return authRes;

  await env.DB.prepare("DELETE FROM tickets WHERE id = ?")
    .bind(params.id)
    .run();
  return new Response("Deleted");
});

export default {
  fetch: (req, env, ctx) => router.handle(req, env, ctx),
};
