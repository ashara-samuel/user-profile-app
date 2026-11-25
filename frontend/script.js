const authView = document.getElementById("auth-view");
const profileView = document.getElementById("profile-view");
const verifyView = document.getElementById("verify-view");
const authMessage = document.getElementById("auth-message");
const profileMessage = document.getElementById("profile-message");
const authForm = document.getElementById("auth-form");
const resetForm = document.getElementById("reset-form");
const newPasswordForm = document.getElementById("new-password-form");
const query = new URLSearchParams(window.location.search);
let authMode = "login";
let resetToken = query.get("reset");
let verifyToken = query.get("verify");
let nextCursor = null;
let profileSearch = "";

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    credentials: "same-origin",
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || "Something went wrong. Please try again.");
    error.status = response.status;
    throw error;
  }
  return payload;
}

function showNotice(element, message, kind = "error") {
  element.textContent = message;
  element.className = `notice ${kind}`;
}

function clearNotice(element) {
  element.textContent = "";
  element.className = "notice hidden";
}

function makeAvatar(name, url, className) {
  const fallback = document.createElement("span");
  fallback.className = className;
  fallback.setAttribute("aria-hidden", "true");
  fallback.textContent = (name || "G").slice(0, 1).toUpperCase();
  if (!url) return fallback;
  const image = document.createElement("img");
  image.className = className;
  image.src = url;
  image.alt = "";
  image.loading = "lazy";
  image.referrerPolicy = "no-referrer";
  image.addEventListener("error", () => image.replaceWith(fallback), { once: true });
  return image;
}

function setAuthMode(mode) {
  authMode = mode;
  document.getElementById("auth-tabs").classList.remove("hidden");
  clearNotice(authMessage);
  const registering = mode === "register";
  document.getElementById("name-field").classList.toggle("hidden", !registering);
  document.getElementById("password").autocomplete = registering ? "new-password" : "current-password";
  document.getElementById("password").required = true;
  document.getElementById("login-tab").classList.toggle("active", !registering);
  document.getElementById("register-tab").classList.toggle("active", registering);
  document.getElementById("login-tab").setAttribute("aria-selected", String(!registering));
  document.getElementById("register-tab").setAttribute("aria-selected", String(registering));
  document.getElementById("auth-submit").innerHTML = registering ? 'Create account <span aria-hidden="true">→</span>' : 'Sign in <span aria-hidden="true">→</span>';
  document.getElementById("forgot-button").classList.toggle("hidden", registering);
}

function showAuth() {
  authView.classList.remove("hidden");
  profileView.classList.add("hidden");
  verifyView.classList.add("hidden");
  authForm.reset();
  authForm.classList.remove("hidden");
  resetForm.classList.add("hidden");
  newPasswordForm.classList.add("hidden");
  setAuthMode("login");
  document.getElementById("logout-button").classList.add("hidden");
}

function showVerification() {
  authView.classList.add("hidden");
  profileView.classList.add("hidden");
  verifyView.classList.remove("hidden");
  document.getElementById("logout-button").classList.add("hidden");
}

function showProfile(user) {
  authView.classList.add("hidden");
  verifyView.classList.add("hidden");
  profileView.classList.remove("hidden");
  document.getElementById("logout-button").classList.remove("hidden");
  document.getElementById("welcome-title").textContent = `Welcome back, ${user.name}.`;
  document.getElementById("profile-name").value = user.name || "";
  document.getElementById("profile-email").value = user.email || "";
  document.getElementById("bio").value = user.bio || "";
  document.getElementById("location").value = user.location || "";
  document.getElementById("website").value = user.website || "";
  document.getElementById("avatar-url").value = user.avatarUrl || "";
  document.getElementById("visibility").value = user.visibility || "public";
  document.getElementById("avatar-preview").replaceChildren(makeAvatar(user.name, user.avatarUrl, "avatar"));
  clearNotice(profileMessage);
  loadProfiles(true).catch(error => showNotice(profileMessage, error.message));
}

document.getElementById("login-tab").addEventListener("click", () => setAuthMode("login"));
document.getElementById("register-tab").addEventListener("click", () => setAuthMode("register"));

authForm.addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(authForm);
  const body = { email: form.get("email"), password: form.get("password") };
  if (authMode === "register") body.name = form.get("name");
  const button = document.getElementById("auth-submit");
  button.disabled = true;
  try {
    const result = await api(`/auth/${authMode === "register" ? "register" : "login"}`, {
      method: "POST",
      body: JSON.stringify(body)
    });
    if (authMode === "register") {
      document.getElementById("verify-email").value = body.email;
    }
    authForm.reset();
    if (authMode === "register" && !result.user) {
      document.getElementById("verify-message").textContent = result.message;
      showVerification();
      return;
    }
    showProfile(result.user);
  } catch (error) {
    showNotice(authMessage, error.message);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("avatar-url").addEventListener("change", event => {
  document.getElementById("avatar-preview").replaceChildren(
    makeAvatar(document.getElementById("profile-name").value, event.currentTarget.value, "avatar")
  );
});

document.getElementById("forgot-button").addEventListener("click", () => {
  authForm.classList.add("hidden");
  resetForm.classList.remove("hidden");
  document.getElementById("auth-tabs").classList.add("hidden");
  document.getElementById("forgot-button").classList.add("hidden");
  clearNotice(authMessage);
});

document.getElementById("back-to-login").addEventListener("click", () => {
  resetForm.classList.add("hidden");
  authForm.classList.remove("hidden");
  document.getElementById("auth-tabs").classList.remove("hidden");
  document.getElementById("forgot-button").classList.remove("hidden");
  clearNotice(authMessage);
});

resetForm.addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const result = await api("/auth/password-reset", {
      method: "POST",
      body: JSON.stringify({ email: new FormData(resetForm).get("email") })
    });
    showNotice(authMessage, result.message, "success");
    resetForm.reset();
  } catch (error) {
    showNotice(authMessage, error.message);
  }
});

newPasswordForm.addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const result = await api("/auth/password-reset/confirm", {
      method: "POST",
      body: JSON.stringify({ token: resetToken, password: new FormData(newPasswordForm).get("password") })
    });
    showAuth();
    authForm.classList.remove("hidden");
    newPasswordForm.classList.add("hidden");
    setAuthMode("login");
    showNotice(authMessage, result.message, "success");
    history.replaceState(null, "", "/");
  } catch (error) {
    showNotice(authMessage, error.message);
  }
});

document.getElementById("verify-button").addEventListener("click", async () => {
  if (!verifyToken) {
    showVerification();
    document.getElementById("verify-message").textContent = "Open the verification link in your email, then sign in.";
    return;
  }
  try {
    const result = await api("/auth/verify", { method: "POST", body: JSON.stringify({ token: verifyToken }) });
    history.replaceState(null, "", "/");
    showProfile(result.user);
  } catch (error) {
    document.getElementById("verify-message").textContent = error.message;
  }
});

document.getElementById("verify-resend-form").addEventListener("submit", async event => {
  event.preventDefault();
  const message = document.getElementById("verify-resend-message");
  try {
    const result = await api("/auth/verification", {
      method: "POST",
      body: JSON.stringify({ email: new FormData(event.currentTarget).get("email") })
    });
    showNotice(message, result.message, "success");
  } catch (error) {
    showNotice(message, error.message);
  }
});

document.getElementById("profile-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const body = Object.fromEntries(["name", "bio", "location", "website", "avatarUrl", "visibility"].map(key => [key, form.get(key)]));
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const result = await api("/me", { method: "PATCH", body: JSON.stringify(body) });
    showProfile(result.user);
    showNotice(profileMessage, "Your changes are saved.", "success");
  } catch (error) {
    showNotice(profileMessage, error.message);
  } finally {
    button.disabled = false;
  }
});

async function loadProfiles(reset) {
  if (reset) {
    nextCursor = null;
    document.getElementById("profiles-list").replaceChildren();
  }
  const params = new URLSearchParams({ limit: "10" });
  if (profileSearch) params.set("search", profileSearch);
  if (nextCursor) params.set("cursor", nextCursor);
  const result = await api(`/profiles?${params}`);
  const list = document.getElementById("profiles-list");
  for (const profile of result.profiles) {
    const card = document.createElement("article");
    card.className = "person-card";
    const avatar = makeAvatar(profile.name, profile.avatarUrl, "person-avatar");
    const details = document.createElement("div");
    details.className = "person-details";
    const name = document.createElement("h3");
    name.textContent = profile.name;
    details.append(name);
    if (profile.location) {
      const location = document.createElement("p");
      location.textContent = profile.location;
      details.append(location);
    }
    if (profile.bio) {
      const bio = document.createElement("p");
      bio.textContent = profile.bio;
      details.append(bio);
    }
    card.append(avatar, details);
    if (profile.website) {
      const website = document.createElement("a");
      website.className = "person-link";
      website.href = profile.website;
      website.target = "_blank";
      website.rel = "noopener noreferrer";
      website.textContent = "↗";
      website.setAttribute("aria-label", `Visit ${profile.name}'s website`);
      card.append(website);
    }
    list.append(card);
  }
  if (reset && !result.profiles.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No profiles found. Try a different name.";
    list.append(empty);
  }
  nextCursor = result.nextCursor;
  document.getElementById("more-profiles").classList.toggle("hidden", !result.hasMore);
}

document.getElementById("search-form").addEventListener("submit", event => {
  event.preventDefault();
  profileSearch = document.getElementById("search").value.trim();
  loadProfiles(true).catch(error => showNotice(profileMessage, error.message));
});

document.getElementById("more-profiles").addEventListener("click", () => {
  loadProfiles(false).catch(error => showNotice(profileMessage, error.message));
});

document.getElementById("logout-button").addEventListener("click", async () => {
  try {
    await api("/auth/logout", { method: "POST" });
    showAuth();
  } catch (error) {
    showNotice(profileMessage, error.message);
  }
});

document.getElementById("delete-account").addEventListener("click", async () => {
  if (!window.confirm("Delete your account and all associated profile data? This cannot be undone.")) return;
  try {
    await api("/me", { method: "DELETE" });
    showAuth();
    setAuthMode("login");
  } catch (error) {
    showNotice(profileMessage, error.message);
  }
});

async function initialize() {
  if (resetToken) {
    authView.classList.remove("hidden");
    authForm.classList.add("hidden");
    document.getElementById("auth-tabs").classList.add("hidden");
    document.getElementById("forgot-button").classList.add("hidden");
    newPasswordForm.classList.remove("hidden");
    return;
  }
  if (verifyToken) {
    showVerification();
    document.getElementById("verify-message").textContent = "Your email is ready to verify. Continue to activate your account.";
    return;
  }
  try {
    const result = await api("/me");
    showProfile(result.user);
  } catch (error) {
    showAuth();
    setAuthMode("login");
    if (error.status !== 401) showNotice(authMessage, error.message);
  }
}

initialize();
