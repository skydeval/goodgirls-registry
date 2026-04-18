const VERSION = "0.95";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const host = url.hostname;
    const path = url.pathname;
    const method = request.method;

    const parts = host.split(".");
    const sub = parts[0];

    async function hashString(value) {
      const enc = new TextEncoder();
      const data = enc.encode(value);
      const digest = await crypto.subtle.digest("SHA-256", data);
      return [...new Uint8Array(digest)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    }

    function generateGoodgirlsKey(length = 24) {
      const chars = "abcdefghjkmnpqrstuvwxyz23456789";
      let out = "";
      const arr = new Uint8Array(length);
      crypto.getRandomValues(arr);
      for (let i = 0; i < length; i++) {
        out += chars[arr[i] % chars.length];
      }
      return out;
    }

    async function resolveHandleToDid(handle) {
      let h = handle.trim().toLowerCase();
      if (h.startsWith("@")) h = h.slice(1);

      const res = await fetch(
        "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=" +
          encodeURIComponent(h)
      );
      if (!res.ok) return null;

      const data = await res.json();
      return data.did || null;
    }

    // -------------------------------
    // DID VERIFICATION
    // -------------------------------
    if (path === "/.well-known/atproto-did") {
      if (!sub || sub === "goodgirls")
        return new Response("no subdomain", { status: 400 });

      const did = await env.DIDS.get(sub);
      if (!did) return new Response("not found", { status: 404 });

      return new Response(did, { status: 200 });
    }

    // -------------------------------
    // REGISTER (CREATE)
    // -------------------------------
    if (path === "/register" && method === "POST") {
      const overrideToken = request.headers.get("x-goodgirls-token");
      const isAdmin =
        overrideToken &&
        env.REGISTER_TOKEN &&
        overrideToken === env.REGISTER_TOKEN;

      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ ok: false, error: "bad JSON" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const subdomain = (body.subdomain || "").trim().toLowerCase();
      const handle = (body.handle || "").trim();

      if (!subdomain || !handle)
        return new Response(
          JSON.stringify({ ok: false, error: "required fields missing" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );

      const did = await resolveHandleToDid(handle);
      if (!did)
        return new Response(
          JSON.stringify({ ok: false, error: "could not resolve handle" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );

      const secretKey = "secret:" + did;
      const storedHash = await env.DIDS.get(secretKey);

      if (isAdmin) {
        await env.DIDS.put(subdomain, did);
        return new Response(
          JSON.stringify({
            ok: true,
            handle: subdomain + ".goodgirls.onl",
            did,
            mode: "admin"
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      if (!storedHash) {
        const key = generateGoodgirlsKey();
        const keyHash = await hashString(key);

        await env.DIDS.put(secretKey, keyHash);
        await env.DIDS.put(subdomain, did);

        return new Response(
          JSON.stringify({
            ok: true,
            handle: subdomain + ".goodgirls.onl",
            did,
            goodgirls_key: key
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      return new Response(
        JSON.stringify({
          ok: false,
          code: "existing_key_requires_management",
          error: "this DID already has a key"
        }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }

    // -------------------------------
    // MANAGE (UPDATE)
    // -------------------------------
    if (path === "/manage" && method === "POST") {
      let data;
      try {
        data = await request.json();
      } catch {
        return new Response(JSON.stringify({ ok: false, error: "bad JSON" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const handle = data.handle?.trim();
      const key = data.key?.trim();
      const subdomain = (data.subdomain || "").trim().toLowerCase();

      if (!handle || !key || !subdomain)
        return new Response(
          JSON.stringify({ ok: false, error: "missing fields" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );

      const did = await resolveHandleToDid(handle);
      if (!did)
        return new Response(
          JSON.stringify({ ok: false, error: "cannot resolve handle" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );

      const stored = await env.DIDS.get("secret:" + did);
      if (!stored)
        return new Response(
          JSON.stringify({ ok: false, error: "no goodgirls key exists" }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );

      const keyHash = await hashString(key);
      if (keyHash !== stored)
        return new Response(
          JSON.stringify({ ok: false, error: "wrong key" }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );

      await env.DIDS.put(subdomain, did);

      return new Response(
        JSON.stringify({
          ok: true,
          handle: subdomain + ".goodgirls.onl",
          did
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    // -------------------------------
    // DELETE (USER-FACING API)
    // -------------------------------
    if (path === "/delete" && method === "POST") {
      let data;
      try {
        data = await request.json();
      } catch {
        return new Response(JSON.stringify({ ok: false, error: "bad JSON" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const handle = data.handle?.trim();
      const key = data.key?.trim();
      const confirm = data.confirm?.trim();
      const rawSub = (data.subdomain || "").trim().toLowerCase();

      if (!handle || !key || !confirm)
        return new Response(
          JSON.stringify({ ok: false, error: "missing fields" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );

      if (confirm !== "DELETE")
        return new Response(
          JSON.stringify({ ok: false, error: "must type DELETE" }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );

      const did = await resolveHandleToDid(handle);
      if (!did)
        return new Response(
          JSON.stringify({ ok: false, error: "cannot resolve handle" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );

      const secretKey = "secret:" + did;
      const storedHash = await env.DIDS.get(secretKey);
      if (!storedHash)
        return new Response(
          JSON.stringify({
            ok: false,
            error: "this goodgirls handle does not exist"
          }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );

      const keyHash = await hashString(key);
      if (storedHash !== keyHash)
        return new Response(
          JSON.stringify({ ok: false, error: "wrong key" }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );

      // find all subdomains linked to this DID
      let subdomainsToDelete = [];

      if (rawSub) {
        subdomainsToDelete.push(rawSub);
      } else {
        const list = await env.DIDS.list();
        for (const k of list.keys) {
          if (k.name.startsWith("secret:")) continue;
          const v = await env.DIDS.get(k.name);
          if (v === did) subdomainsToDelete.push(k.name);
        }
      }

      if (subdomainsToDelete.length === 0) {
        return new Response(
          JSON.stringify({
            ok: false,
            error: "no handles found for this DID"
          }),
          { status: 404, headers: { "Content-Type": "application/json" } }
        );
      }

      for (const sd of subdomainsToDelete) {
        await env.DIDS.delete(sd);
      }

      await env.DIDS.delete(secretKey);

      const deletedHandles = subdomainsToDelete
        .map(sd => sd + ".goodgirls.onl")
        .join(", ");

      return new Response(
        JSON.stringify({
          ok: true,
          deleted: deletedHandles,
          did
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    // -------------------------------
    // ADMIN JSON APIs for /gg console
    // -------------------------------
    if (path === "/gg/api/list" && method === "POST") {
      let data;
      try {
        data = await request.json();
      } catch {
        return new Response(JSON.stringify({ ok: false, error: "bad JSON" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const token = (data.token || "").trim();
      const cursor = data.cursor || undefined;

      if (!env.REGISTER_TOKEN) {
        return new Response(
          JSON.stringify({ ok: false, error: "admin token not configured" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      if (token !== env.REGISTER_TOKEN) {
        return new Response(
          JSON.stringify({ ok: false, error: "incorrect admin token" }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }

      const list = await env.DIDS.list({ limit: 100, cursor });

      const visibleKeys = list.keys.filter(k => !k.name.startsWith("secret:"));
      const entries = await Promise.all(
        visibleKeys.map(async k => {
          const did = await env.DIDS.get(k.name);
          return { subdomain: k.name, did: did || "" };
        })
      );

      return new Response(
        JSON.stringify({
          ok: true,
          entries,
          cursor: list.cursor || null,
          list_complete: !!list.list_complete
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    if (path === "/gg/api/delete" && method === "POST") {
      // kept for fallback, not used by row button anymore
      let data;
      try {
        data = await request.json();
      } catch {
        return new Response(JSON.stringify({ ok: false, error: "bad JSON" }), {
          status: 400,
          headers: { "Content-Type": "application/json" } }
        );
      }

      const token = (data.token || "").trim();
      const rawSub = (data.subdomain || "").trim().toLowerCase();

      if (!env.REGISTER_TOKEN) {
        return new Response(
          JSON.stringify({ ok: false, error: "admin token not configured" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      if (token !== env.REGISTER_TOKEN) {
        return new Response(
          JSON.stringify({ ok: false, error: "incorrect admin token" }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }

      if (!rawSub) {
        return new Response(
          JSON.stringify({ ok: false, error: "missing subdomain" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      const existingDid = await env.DIDS.get(rawSub);
      if (!existingDid) {
        return new Response(
          JSON.stringify({
            ok: false,
            error: "this goodgirls handle does not exist"
          }),
          { status: 404, headers: { "Content-Type": "application/json" } }
        );
      }

      await env.DIDS.delete(rawSub);

      return new Response(
        JSON.stringify({
          ok: true,
          deleted: rawSub + ".goodgirls.onl",
          did: existingDid
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    if (path === "/gg/api/wipe-did" && method === "POST") {
      let data;
      try {
        data = await request.json();
      } catch {
        return new Response(JSON.stringify({ ok: false, error: "bad JSON" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const token = (data.token || "").trim();
      const did = (data.did || "").trim();

      if (!env.REGISTER_TOKEN) {
        return new Response(
          JSON.stringify({ ok: false, error: "admin token not configured" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      if (token !== env.REGISTER_TOKEN) {
        return new Response(
          JSON.stringify({ ok: false, error: "incorrect admin token" }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }

      if (!did) {
        return new Response(
          JSON.stringify({ ok: false, error: "missing did" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      const secretKey = "secret:" + did;
      const secret = await env.DIDS.get(secretKey);
      if (!secret) {
        return new Response(
          JSON.stringify({
            ok: false,
            error: "this goodgirls handle does not exist"
          }),
          { status: 404, headers: { "Content-Type": "application/json" } }
        );
      }

      let cursor = undefined;
      const deletedSubdomains = [];

      do {
        const page = await env.DIDS.list({ limit: 100, cursor });
        for (const k of page.keys) {
          if (k.name.startsWith("secret:")) continue;
          const v = await env.DIDS.get(k.name);
          if (v === did) {
            await env.DIDS.delete(k.name);
            deletedSubdomains.push(k.name);
          }
        }
        cursor = page.cursor;
      } while (cursor);

      await env.DIDS.delete(secretKey);

      const deletedHandles = deletedSubdomains.map(sd => sd + ".goodgirls.onl");

      return new Response(
        JSON.stringify({
          ok: true,
          did,
          deleted: deletedHandles
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    // -------------------------------
    // /manage PAGE (no OG meta)
    // -------------------------------
    if (path === "/manage" && method === "GET") {
      const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>manage your goodgirls.onl handle</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
:root{
  --bg:#151515;
  --text:#eee;
  --label:#ccc;
  --input-bg:#1f1f1f;
  --input-border:#444;
  --purple:#a060ff;
}

body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:system-ui,sans-serif;
  min-height:100vh;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:flex-start;
  padding:2rem;
  text-align:center;
}

h1{
  font-size:1.2rem;
  margin-bottom:1rem;
}
.accent{ color:var(--purple); }

form{
  width:100%;
  max-width:360px;
  text-align:left;
}

label{
  display:block;
  margin-top:1rem;
  margin-bottom:0.3rem;
  font-size:0.9rem;
  color:var(--label);
}

input{
  width:100%;
  padding:0.55rem;
  border-radius:6px;
  background:var(--input-bg);
  border:1px solid var(--input-border);
  color:#ccc;
  box-sizing:border-box;
}

input::placeholder{ color:#777; }

button{
  margin-top:1.4rem;
  width:100%;
  padding:0.6rem;
  background:#3a3a3a;
  border:none;
  border-radius:6px;
  color:var(--text);
  font-weight:600;
  cursor:pointer;
  text-transform:none;
  font-size:0.9rem;
}

#showDelete{
  margin-top:1rem;
  width:auto;
  padding:0.35rem 0.8rem;
  border-radius:999px;
  font-size:0.8rem;
  background:#2a2a2a;
}
#showDelete:hover{
  background:#662222;
}

#deleteBox{
  display:none;
  margin-top:2rem;
  padding-top:1.2rem;
  border-top:1px solid #333;
}

#result{
  margin-top:1rem;
  font-size:0.85rem;
  color:#aaa;
  white-space:pre-wrap;
}
</style>
</head>

<body>

<h1>manage your <span class="accent">goodgirls.onl</span> handle</h1>

<form id="manageForm">

  <label>current handle</label>
  <input id="handle" placeholder="e.g. alice.bsky.social" required />

  <label>your goodgirls key</label>
  <input id="key" placeholder="your key" required />

  <label>new desired handle</label>
  <input id="subdomain" placeholder="newname" required />

  <button type="submit">update handle</button>
</form>

<button id="showDelete">delete this handle</button>

<div id="deleteBox">
  <form id="deleteForm">

    <label>type DELETE to confirm</label>
    <input id="confirm" placeholder="DELETE" />

    <button type="submit" style="background:#662222;">delete</button>
  </form>
</div>

<div id="result"></div>

<script>
const result=document.getElementById("result");

document.getElementById("showDelete").onclick=()=>{
  document.getElementById("deleteBox").style.display="block";
};

document.getElementById("manageForm").addEventListener("submit",async(e)=>{
  e.preventDefault();
  result.textContent="";

  const handle=document.getElementById("handle").value.trim();
  const key=document.getElementById("key").value.trim();
  const sub=document.getElementById("subdomain").value.trim().toLowerCase();

  const btn=e.target.querySelector("button");
  btn.disabled=true;

  const res=await fetch("/manage",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({handle,key,subdomain:sub})
  });

  const data=await res.json().catch(()=>({}));

  if(!res.ok||!data.ok){
    result.textContent="Error: "+(data.error||res.statusText);
  }else{
    result.textContent="Updated: "+data.handle+"\\nDID: "+data.did;
  }

  btn.disabled=false;
});

document.getElementById("deleteForm").addEventListener("submit",async(e)=>{
  e.preventDefault();
  result.textContent="";

  const handle=document.getElementById("handle").value.trim();
  const key=document.getElementById("key").value.trim();
  const confirm=document.getElementById("confirm").value.trim();

  const btn=e.target.querySelector("button");
  btn.disabled=true;

  const res=await fetch("/delete",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({handle,key,confirm})
  });

  const data=await res.json().catch(()=>({}));

  if(!res.ok||!data.ok){
    result.textContent="Error: "+(data.error||res.statusText);
  }else{
    result.textContent="Deleted: "+data.deleted+"\\nDID: "+data.did;
  }

  btn.disabled=false;
});
</script>

</body>
</html>`;
      return new Response(html, {
        status: 200,
        headers: { "Content-Type": "text/html" }
      });
    }

    // -------------------------------
    // /gg ADMIN CONSOLE
    // -------------------------------
    if (path === "/gg" && method === "GET") {
      const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>goodgirls handle console</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
:root{
  --bg:#151515;
  --text:#eee;
  --label:#ccc;
  --input-bg:#1f1f1f;
  --input-border:#444;
  --purple:#a060ff;
  --danger:#cc4444;
}

body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:system-ui,sans-serif;
  min-height:100vh;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:flex-start;
  padding:2rem 1rem;
}

h1{
  font-size:1.2rem;
  margin-bottom:1.25rem;
}
h2{
  font-size:0.95rem;
  margin:0.75rem 0 0.25rem;
}
.accent{ color:var(--purple); }

.panel{
  width:100%;
  max-width:720px;
  background:#181818;
  border:none;
  border-radius:10px;
  padding:1rem;
  box-sizing:border-box;
}

label{
  display:block;
  font-size:0.8rem;
  color:var(--label);
  margin-bottom:0.25rem;
}

input{
  width:100%;
  max-width:320px;
  padding:0.45rem;
  border-radius:6px;
  background:var(--input-bg);
  border:1px solid var(--input-border);
  color:#ccc;
  box-sizing:border-box;
  font-size:0.85rem;
}

.token-input{
  background:transparent;
  border:none;
  border-bottom:1px solid var(--input-border);
  border-radius:0;
  padding-left:0;
  padding-right:0;
}

.controls-row{
  display:flex;
  flex-wrap:wrap;
  gap:0.5rem;
  align-items:center;
  margin-top:0.5rem;
  margin-bottom:0.5rem;
}

button{
  padding:0.45rem 0.9rem;
  border-radius:6px;
  border:none;
  background:#2a2a2a;
  color:#fff;
  font-size:0.8rem;
  cursor:pointer;
}
button:hover{
  background:#3a3a3a;
}
button[disabled]{
  opacity:0.4;
  cursor:default;
}

button.danger{
  background:#4a1e1e;
}
button.danger:hover{
  background:#6a2626;
}

.status{
  margin-top:0.5rem;
  font-size:0.8rem;
  color:#aaa;
  white-space:pre-wrap;
}

.small{
  font-size:0.75rem;
  color:#777;
}

.badge{
  display:inline-block;
  padding:0.15rem 0.45rem;
  font-size:0.7rem;
  border-radius:999px;
  border:1px solid var(--input-border);
  color:#aaa;
}

.table-wrap{
  margin-top:0.75rem;
  max-height:60vh;
  overflow:auto;
  border:1px solid #252525;
  border-radius:8px;
}

table{
  width:100%;
  border-collapse:collapse;
  font-size:0.8rem;
}
thead{
  position:sticky;
  top:0;
  background:#1c1c1c;
}
th,td{
  padding:0.4rem 0.5rem;
  text-align:left;
  border-bottom:1px solid #222;
}
th.subcol{ width:40%; }
th.didcol{ width:45%; }
th.actcol{
  width:15%;
  text-align:right;
}
td.actions{
  text-align:right;
}

.version-badge{
  margin-top:1rem;
  font-size:0.7rem;
  color:var(--purple);
  text-align:right;
  opacity:0;
  transition:opacity 0.35s ease;
  pointer-events:none;
}
.version-badge.visible{
  opacity:0.8;
}
</style>
</head>
<body>

<h1>goodgirls <span class="accent">handle</span> console</h1>

<div class="panel">
  <h2>attune your sigil</h2>
  <form id="authForm">
    <input id="token" class="token-input" type="password" autocomplete="off"/>
    <div class="controls-row">
      <button id="unlock" type="submit">wake my console</button>
    </div>
  </form>

  <div id="console" style="display:none; margin-top:1rem;">
    <h2>handles</h2>
    <div class="controls-row">
      <button id="prevPage">prev</button>
      <button id="nextPage">next</button>
      <button id="sortToggle">sort by subdomain (a→z)</button>
      <span class="small"><span id="pageBadge" class="badge">page -</span></span>
    </div>

    <div class="table-wrap" id="tableWrap" style="display:none;">
      <table>
        <thead>
          <tr>
            <th class="subcol">subdomain</th>
            <th class="didcol">DID</th>
            <th class="actcol">actions</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>

    <h2>danger zone</h2>
    <p class="small">wipe a DID from goodgirls: removes all its handles and secret key.</p>
    <div class="controls-row">
      <input id="wipeDidInput" placeholder="did:plc:..." style="max-width:420px;"/>
      <button id="wipeDidBtn" class="danger">wipe DID</button>
    </div>
  </div>

  <div class="status" id="status"></div>
  <div id="versionBadge" class="version-badge"></div>
</div>

<script>
const VERSION = "0.95";

window.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("status");
  const tokenInput = document.getElementById("token");
  const unlockBtn = document.getElementById("unlock");
  const authForm = document.getElementById("authForm");
  const consoleDiv = document.getElementById("console");
  const versionBadge = document.getElementById("versionBadge");

  const prevPageBtn = document.getElementById("prevPage");
  const nextPageBtn = document.getElementById("nextPage");
  const sortToggleBtn = document.getElementById("sortToggle");
  const pageBadge = document.getElementById("pageBadge");
  const tbody = document.getElementById("tbody");
  const tableWrap = document.getElementById("tableWrap");

  const wipeDidInput = document.getElementById("wipeDidInput");
  const wipeDidBtn = document.getElementById("wipeDidBtn");

  function setStatus(msg){
    if(statusEl) statusEl.textContent = msg || "";
  }

  // mystical boot text, but clearly yours
  setStatus("your registry spirit is humming quietly · awaiting your sigil");

  let state = {
    token:"",
    pages:[],
    currentIndex:0,
    sortAsc:true,
    unlocked:false
  };

  function render(){
    if(!state.pages.length){
      tableWrap.style.display = "none";
      pageBadge.textContent = "page -";
      if (state.unlocked) {
        setStatus("the ledger is quiet · no handles are bound here");
      }
      return;
    }

    const page = state.pages[state.currentIndex];
    let entries = page.entries.slice();

    entries.sort((a,b)=>{
      const as = a.subdomain || "";
      const bs = b.subdomain || "";
      if(as < bs) return state.sortAsc ? -1 : 1;
      if(as > bs) return state.sortAsc ? 1 : -1;
      return 0;
    });

    tbody.innerHTML = "";
    for(const row of entries){
      const tr = document.createElement("tr");

      const tdSub = document.createElement("td");
      tdSub.textContent = row.subdomain + ".goodgirls.onl";

      const tdDid = document.createElement("td");
      tdDid.textContent = row.did || "";

      const tdAct = document.createElement("td");
      tdAct.className = "actions";

      const delBtn = document.createElement("button");
      delBtn.textContent = "delete";
      delBtn.className = "danger";
      delBtn.onclick = () => handleDelete(row.subdomain, row.did);

      tdAct.appendChild(delBtn);

      tr.appendChild(tdSub);
      tr.appendChild(tdDid);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }

    tableWrap.style.display = entries.length ? "block" : "none";

    const pageNumber = state.currentIndex + 1;
    pageBadge.textContent = "page " + pageNumber;
    setStatus("peering into page "+pageNumber+" · "+entries.length+" handle(s) glimmer in the dark");

    const pageData = state.pages[state.currentIndex];
    prevPageBtn.disabled = state.currentIndex === 0;
    nextPageBtn.disabled = !pageData || !pageData.cursor;
  }

  async function apiList(cursor){
    const token = tokenInput.value.trim();
    state.token = token;
    const res = await fetch("/gg/api/list",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ token, cursor: cursor || null })
    });
    const data = await res.json().catch(()=>({}));
    if(!res.ok || !data.ok){
      throw new Error(data.error || res.statusText || "list failed");
    }
    return data;
  }

  async function apiDelete(subdomain){
    const res = await fetch("/gg/api/delete",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ token: state.token, subdomain })
    });
    const data = await res.json().catch(()=>({}));
    if(!res.ok || !data.ok){
      throw new Error(data.error || res.statusText || "delete failed");
    }
    return data;
  }

  async function apiWipeDid(did){
    const res = await fetch("/gg/api/wipe-did",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ token: state.token, did })
    });
    const data = await res.json().catch(()=>({}));
    if(!res.ok || !data.ok){
      throw new Error(data.error || res.statusText || "wipe failed");
    }
    return data;
  }

async function unlockConsole(){
  try{
    if (unlockBtn) unlockBtn.disabled = true;
    setStatus("consulting the hidden ledger with your sigil...");
    state.pages = [];
    state.currentIndex = 0;
    state.unlocked = false;
    consoleDiv.style.display = "none";
    versionBadge?.classList.remove("visible");

    const data = await apiList(null);
    state.pages.push({
      entries: data.entries || [],
      cursor: data.cursor || null,
      list_complete: !!data.list_complete
    });
    state.currentIndex = 0;
    state.unlocked = true;
    consoleDiv.style.display = "block";
    document.getElementById("versionBadge").textContent = "v" + VERSION + " · internal build";
    versionBadge?.classList.add("visible");
          render();
    const count = (data.entries && data.entries.length) || 0;
    setStatus("your console awakens · "+count+" thread(s) of fate detected on the first page");
  }catch(err){
    state.unlocked = false;
    consoleDiv.style.display = "none";
    versionBadge?.classList.remove("visible");
    setStatus("the spell fizzled: "+err.message);
  }finally{
    if (unlockBtn) unlockBtn.disabled = false;
  }
}

  if(authForm){
    authForm.addEventListener("submit", (e) => {
      e.preventDefault();
      unlockConsole();
    });
  }

  if(unlockBtn){
    unlockBtn.addEventListener("click", (e) => {
      e.preventDefault();
      unlockConsole();
    });
  }

  if(nextPageBtn){
    nextPageBtn.addEventListener("click", async () => {
      const current = state.pages[state.currentIndex];
      if(!current || !current.cursor) return;

      try{
        nextPageBtn.disabled = true;
        setStatus("turning the next page of the ledger...");
        const data = await apiList(current.cursor);
        state.pages.push({
          entries: data.entries || [],
          cursor: data.cursor || null,
          list_complete: !!data.list_complete
        });
        state.currentIndex = state.pages.length - 1;
        render();
        setStatus("a new page unfolds · page "+(state.currentIndex + 1)+" is now revealed");
      }catch(err){
        setStatus("the pages refuse to turn: "+err.message);
      }finally{
        nextPageBtn.disabled = false;
      }
    });
  }

  if(prevPageBtn){
    prevPageBtn.addEventListener("click", () => {
      if(state.currentIndex === 0) return;
      state.currentIndex -= 1;
      setStatus("slipping back to the previous page...");
      render();
    });
  }

  if(sortToggleBtn){
    sortToggleBtn.addEventListener("click", () => {
      state.sortAsc = !state.sortAsc;
      sortToggleBtn.textContent = state.sortAsc
        ? "sort by subdomain (a→z)"
        : "sort by subdomain (z→a)";
      setStatus("reordering threads by name · the weave shifts to match your will");
      render();
    });
  }

  async function handleDelete(subdomain, did){
    if(!subdomain) return;

    // if we know the DID, treat delete as "nuke this record from existence"
    if(did){
      const sure = confirm(
        "sever all goodgirls records for this DID?\\n\\nDID: " + did + "\\n\\nthis will unbind every handle and its secret key."
      );
      if(!sure) return;

      try{
        setStatus("severing this DID from the weave...");
        const data = await apiWipeDid(did);
        const count = (data.deleted && data.deleted.length) || 0;
        setStatus("DID "+data.did+" forgotten from the registry · "+count+" handle(s) unbound");

        for(const page of state.pages){
          page.entries = page.entries.filter(e => e.did !== did);
        }
        render();
      }catch(err){
        setStatus("the unbinding failed: "+err.message);
      }
      return;
    }

    // fallback: if no DID, just delete that subdomain mapping
    const yes = confirm("unravel "+subdomain+".goodgirls.onl from the tapestry?");
    if(!yes) return;

    try{
      setStatus("snipping the thread for "+subdomain+"...");
      const data = await apiDelete(subdomain);
      setStatus("handle "+data.deleted+" has been gently unraveled");

      const page = state.pages[state.currentIndex];
      page.entries = page.entries.filter(e => e.subdomain !== subdomain);
      render();
    }catch(err){
      setStatus("the scissors slipped: "+err.message);
    }
  }

  if(wipeDidBtn){
    wipeDidBtn.addEventListener("click", async () => {
      const did = (wipeDidInput.value || "").trim();
      if(!did){
        setStatus("whisper a DID to wipe before we begin any unbinding");
        return;
      }

      const sure = confirm(
        "wipe DID "+did+" ?\\n\\nthis will remove all its goodgirls handles and secret key."
      );
      if(!sure) return;

      try{
        wipeDidBtn.disabled = true;
        setStatus("calling the void for DID "+did+"...");
        const data = await apiWipeDid(did);
        const count = (data.deleted && data.deleted.length) || 0;
        setStatus("the void accepts · DID "+data.did+" erased and "+count+" handle(s) released");

        for(const page of state.pages){
          page.entries = page.entries.filter(e => e.did !== did);
        }
        render();
      }catch(err){
        setStatus("the void whispers back an error: "+err.message);
      }finally{
        wipeDidBtn.disabled = false;
      }
    });
  }
});
</script>

</body>
</html>`;
      return new Response(html, {
        status: 200,
        headers: { "Content-Type": "text/html" }
      });
    }

    // -------------------------------
    // ROOT PAGE (CREATE) — OG/Twitter meta for Discord preview
    // -------------------------------
    if (path === "/" && method === "GET") {
      const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>get a goodgirls.onl handle</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="description" content="claim a cute goodgirls.onl handle for your bluesky account"/>
<meta property="og:type" content="website"/>
<meta property="og:title" content="get a goodgirls.onl handle"/>
<meta property="og:description" content="claim a cute goodgirls.onl handle for your bluesky account"/>
<meta property="og:url" content="https://goodgirls.onl/"/>
<meta name="twitter:card" content="summary"/>
<style>
:root {
  --bg:#151515;
  --text:#eee;
  --label:#ccc;
  --input-bg:#1f1f1f;
  --input-border:#444;
  --purple:#a060ff;
}

body {
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:system-ui,sans-serif;
  min-height:100vh;
  display:flex;
  flex-direction:column;
  justify-content:center;
  align-items:center;
  padding:2rem;
  text-align:center;
}

h1 {
  font-size:1.2rem;
  margin-bottom:1rem;
}

.accent { color:var(--purple); }

form {
  width:100%;
  max-width:360px;
  text-align:left;
}

label {
  display:block;
  margin-top:1rem;
  margin-bottom:0.3rem;
  color:var(--label);
  font-size:0.9rem;
}

input{
  width:100%;
  padding:0.55rem;
  border-radius:6px;
  background:var(--input-bg);
  border:1px solid var(--input-border);
  color:#ccc;
  box-sizing:border-box;
}

input::placeholder { color:#777; }

.handle-row {
  display:flex;
  width:100%;
  border:1px solid var(--input-border);
  border-radius:6px;
  background:var(--input-bg);
  box-sizing:border-box;
}

.handle-row input {
  flex:1;
  border:none;
  background:transparent;
  padding:0.55rem;
  color:#ccc;
}

.suffix {
  padding:0.55rem;
  color:var(--purple);
  font-weight:600;
  white-space:nowrap;
}

button {
  margin-top:1.4rem;
  width:100%;
  padding:0.6rem;
  background:#3a3a3a;
  border:none;
  border-radius:6px;
  color:var(--text);
  font-weight:600;
  cursor:pointer;
  text-transform:none;
  font-size:0.9rem;
}

.divider {
  width:100%;
  max-width:360px;
  margin:1.5rem 0;
  height:1px;
  background:#333;
}

.subtext {
  margin-top:0.5rem;
  font-size:0.85rem;
  color:#aaa;
}

.manage-btn {
  margin-top:1rem;
  padding:0.6rem;
  width:100%;
  max-width:360px;
  background:#2a2a2a;
  border:1px solid var(--input-border);
  border-radius:6px;
  color:var(--text);
  cursor:pointer;
  font-size:0.9rem;
}
.manage-btn:hover {
  background:#3a3a3a;
}

#result{
  margin-top:1rem;
  font-size:0.85rem;
  color:#aaa;
  white-space:pre-wrap;
  text-align:left;
  max-width:360px;
}

.steps{
  margin:0.5rem 0 0;
  padding-left:1.25rem;
}
.steps li{
  margin-bottom:0.25rem;
}
.hl{
  font-weight:600;
}

.copy-btn{
  display:inline-block;
  width:auto;
  margin-left:0.4rem;
  margin-top:0;
  padding:0.1rem 0.35rem;
  border-radius:999px;
  border:1px solid var(--input-border);
  background:#2a2a2a;
  color:#eee;
  font-size:0.7rem;
  cursor:pointer;
  line-height:1.2;
  vertical-align:baseline;
}
.copy-btn:hover{ background:#3a3a3a; }

.toggle-btn{
  margin-top:0.75rem;
  padding:0.35rem 0.8rem;
  border-radius:999px;
  border:1px solid var(--input-border);
  background:#2a2a2a;
  color:#eee;
  font-size:0.75rem;
  cursor:pointer;
}
.toggle-btn:hover{
  background:#3a3a3a;
}
</style>
</head>

<body>

<h1>get a <span class="accent">goodgirls.onl</span> handle</h1>

<form id="f">

  <label>current handle</label>
  <input id="handle" placeholder="e.g. alice.bsky.social" required />

  <label>desired handle</label>
  <div class="handle-row">
    <input id="subdomain" placeholder="alice" required />
    <span class="suffix">.goodgirls.onl</span>
  </div>

  <button>submit</button>
</form>

<div class="divider"></div>

<div class="subtext">if you want to change or delete your handle</div>

<div>
  <button class="manage-btn" onclick="location.href='/manage'">manage</button>
</div>

<div id="result"></div>

<script>
const f=document.getElementById("f");
const r=document.getElementById("result");

function escapeHtml(str){
  return String(str||"").replace(/[&<>"']/g, c=>{
    switch(c){
      case "&":return "&amp;";
      case "<":return "&lt;";
      case ">":return "&gt;";
      case '"':return "&quot;";
      case "'":return "&#39;";
      default:return c;
    }
  });
}

async function copyToClipboard(text){
  try{
    await navigator.clipboard.writeText(text);
  }catch(e){}
}

f.addEventListener("submit",async e=>{
  e.preventDefault();
  r.textContent="";
  r.innerHTML="";

  const handle=document.getElementById("handle").value.trim();
  const sub=document.getElementById("subdomain").value.trim().toLowerCase();

  if(!handle||!sub){
    r.textContent="Please fill out all fields.";
    return;
  }

  const btn=f.querySelector("button");
  btn.disabled=true;

  try{
    const res=await fetch("/register",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({handle,subdomain:sub})
    });
    const data=await res.json().catch(()=>({}));

    if(!res.ok||!data.ok){
      if(data.code==="existing_key_requires_management"){
        r.textContent="this Bluesky account already has a goodgirls key. use the manage page.";
      } else {
        r.textContent="Error: "+(data.error||res.statusText);
      }
    } else {
      const handleDisplay=data.handle||(sub+".goodgirls.onl");

      if(data.goodgirls_key){
        let html=""
          +"<div><strong>handle:</strong> "+escapeHtml(handleDisplay)
          +" <button class=\\"copy-btn\\" id=\\"copy-handle\\">copy</button></div>"
          +"<div><strong>DID:</strong> "+escapeHtml(data.did||"")+"</div>"
          +"<div style=\\"margin-top:0.75rem;\\"><strong>save this secret password:</strong><br>"
          +"<code>"+escapeHtml(data.goodgirls_key)+"</code>"
          +" <button class=\\"copy-btn\\" id=\\"copy-key\\">copy</button></div>"
          +"<button id=\\"toggle-instructions\\" class=\\"toggle-btn\\">show instructions</button>"
          +"<div id=\\"instructions\\" style=\\"display:none;margin-top:0.75rem;\\">"
          +"<div>to apply your new goodgirls handle:</div>"
          +"<ol class=\\"steps\\">"
          +"<li><span class=\\"hl\\">in Bluesky, go to settings → account → @handle</span></li>"
          +"<li><span class=\\"hl\\">click \\"I have my own domain\\" at the bottom</span></li>"
          +"<li><span class=\\"hl\\">in the box at the top, type </span><code>"+escapeHtml(handleDisplay)+"</code></li>"
          +"<li><span class=\\"hl\\">click \\"no dns panel\\" tab at the top</span></li>"
          +"<li><span class=\\"hl\\">click \\"verify text file\\"</span></li>"
          +"<li><span class=\\"hl\\">once it shows as verified, click \\"update handle\\"</span></li>"
          +"</ol></div>";

        r.innerHTML=html;

        const copyHandle=document.getElementById("copy-handle");
        const copyKey=document.getElementById("copy-key");
        copyHandle?.addEventListener("click",()=>copyToClipboard(handleDisplay));
        copyKey?.addEventListener("click",()=>copyToClipboard(data.goodgirls_key));

        const toggle=document.getElementById("toggle-instructions");
        const box=document.getElementById("instructions");
        toggle.addEventListener("click",()=>{
          const open=box.style.display!=="none";
          box.style.display=open?"none":"block";
          toggle.textContent=open?"show instructions":"hide instructions";
        });

      } else {
        let out="handle: "+handleDisplay+"\\nDID: "+(data.did||"");
        r.textContent=out;
      }
    }

  }catch(err){
    r.textContent="Network error: "+err;
  }

  btn.disabled=false;
});
</script>

</body>
</html>`;
      return new Response(html, {
        status: 200,
        headers:{"Content-Type":"text/html"}
      });
    }

    // fallback
    return new Response("Not found", { status: 404 });
  }
};
