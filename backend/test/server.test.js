const test = require("node:test");
const assert = require("node:assert/strict");
const { app, hashPassword, verifyPassword, validateProfile, publicUser } = require("../server");

test("password hashes are salted and verify only the matching password", async () => {
  const firstHash = await hashPassword("long-enough-password");
  const secondHash = await hashPassword("long-enough-password");

  assert.notEqual(firstHash, secondHash);
  assert.equal(await verifyPassword("long-enough-password", firstHash), true);
  assert.equal(await verifyPassword("not-the-password", firstHash), false);
  assert.equal(await verifyPassword("anything", "malformed"), false);
});

test("registration validation normalizes email and rejects short passwords", () => {
  const valid = validateProfile({ name: "  Alex  ", email: " ALEX@EXAMPLE.COM ", password: "long-enough-password" }, { registration: true });
  assert.deepEqual(valid.errors, {});
  assert.equal(valid.value.name, "Alex");
  assert.equal(valid.value.email, "alex@example.com");
  assert.equal(valid.value.password, "long-enough-password");

  const invalid = validateProfile({ name: "", email: "bad-email", password: "short" }, { registration: true });
  assert.deepEqual(Object.keys(invalid.errors).sort(), ["email", "name", "password"]);
});

test("profile updates allow only validated profile fields", () => {
  const result = validateProfile({
    name: "Sam",
    bio: " hello ",
    website: "javascript:alert(1)",
    passwordHash: "attacker-value",
    visibility: "friends"
  });

  assert.equal(result.value.name, "Sam");
  assert.equal(result.value.bio, "hello");
  assert.equal(Object.hasOwn(result.value, "passwordHash"), false);
  assert.equal(result.errors.website, "website must be a valid HTTP or HTTPS URL.");
  assert.equal(result.errors.visibility, "Visibility must be public or private.");
});

test("public user serialization omits password hashes and internal fields", () => {
  const result = publicUser({
    _id: "user-id", name: "Sam", email: "sam@example.com",
    passwordHash: "secret", bio: "", location: "", website: "",
    avatarUrl: "", visibility: "public", emailVerified: true, createdAt: new Date()
  });

  assert.equal(result.id, "user-id");
  assert.equal(Object.hasOwn(result, "passwordHash"), false);
});

test("API rejects invalid login details and reports database readiness", async () => {
  const server = app.listen(0);
  await new Promise(resolve => server.once("listening", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;

  try {
    const login = await fetch(`${origin}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "not-an-email", password: "" })
    });
    assert.equal(login.status, 400);
    assert.equal(login.headers.get("x-content-type-options"), "nosniff");

    const verification = await fetch(`${origin}/api/auth/verification`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "not-an-email" })
    });
    assert.equal(verification.status, 200);
    assert.deepEqual(await verification.json(), {
      message: "If the account needs verification, a link will be sent."
    });

    const health = await fetch(`${origin}/api/health`);
    assert.equal(health.status, 503);
    assert.deepEqual(await health.json(), { status: "unavailable" });
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
