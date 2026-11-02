<script setup lang="ts">
// The early-access form. With no backend of our own, it opens the visitor's mail client with the answers filled in,
// addressed to the project. Set ENDPOINT to a form service URL to post silently instead; the same fields are sent as JSON.
import { computed, ref } from "vue";

const ENDPOINT = "";
const TO = "partha@charioteerconsulting.com";

const email = ref("");
const agents = ref("");
const stores = ref("");
const proof = ref("");
const note = ref("");
const sent = ref(false);
/** the mail client was opened; whether the mail went is the visitor's to know, so the page does not claim it */
const opened = ref(false);
const error = ref("");
const busy = ref(false);

const valid = computed(() => /.+@.+\..+/.test(email.value) && agents.value.trim().length > 0);

function body() {
  return `Email: ${email.value}\n\nWhat agents do you run, on what data?\n${agents.value}\n\nWhich memory or retrieval stores do you use?\n${stores.value || "(none)"}\n\nHas an auditor, customer, or regulator asked you to prove what an agent did?\n${proof.value || "(not answered)"}\n\nAnything else:\n${note.value || "(nothing)"}\n`;
}

async function submit() {
  error.value = "";
  if (!valid.value) {
    error.value = "An email address and the first answer are needed.";
    return;
  }
  if (ENDPOINT) {
    busy.value = true;
    try {
      const res = await fetch(ENDPOINT, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ email: email.value, agents: agents.value, stores: stores.value, proof: proof.value, note: note.value, source: "agent-custody.dev/early-access" }) });
      if (!res.ok) throw new Error(`the form service answered ${res.status}`);
      sent.value = true;
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
    } finally {
      busy.value = false;
    }
    return;
  }
  window.location.href = `mailto:${TO}?subject=${encodeURIComponent("agent-custody early access")}&body=${encodeURIComponent(body())}`;
  opened.value = true;
}

async function copyRequest() {
  await navigator.clipboard.writeText(`To: ${TO}\nSubject: agent-custody early access\n\n${body()}`);
  error.value = "";
  copied.value = true;
}
const copied = ref(false);
</script>

<template>
  <form class="early" @submit.prevent="submit">
    <label>Work email<input v-model="email" type="email" required placeholder="you@company.com" /></label>
    <label>What agents do you run, and on what data? <span class="req">required</span><textarea v-model="agents" rows="3" placeholder="e.g. a support agent on Zendesk and our CRM; a coding agent on internal repos"></textarea></label>
    <label>Which memory or retrieval stores do you use, if any?<input v-model="stores" placeholder="Mem0, Zep, Letta, pgvector, none" /></label>
    <label>Has an auditor, customer, or regulator asked you to prove what an agent did?
      <select v-model="proof">
        <option value="">choose one</option>
        <option>yes, already</option>
        <option>expected within a year</option>
        <option>no</option>
      </select>
    </label>
    <label>Anything else<textarea v-model="note" rows="2"></textarea></label>
    <div class="row">
      <button type="submit" :disabled="busy || sent">{{ sent ? "Sent" : busy ? "Sending…" : opened ? "Open my mail app again" : "Request early access" }}</button>
      <span v-if="sent" class="ok">Thank you. We answer every request.</span>
      <span v-else-if="opened" class="ok">Your mail app should have opened with the request filled in; send it from there. If nothing opened, <button type="button" class="link" @click="copyRequest">{{ copied ? "copied" : "copy the request" }}</button> and email it to {{ TO }}.</span>
      <span v-if="error" class="err">{{ error }}</span>
    </div>
    <p class="note">Your answers go to {{ TO }} and nowhere else. No account, no tracking.</p>
  </form>
</template>

<style scoped>
.early { display: grid; gap: 0.9rem; margin: 1.5rem 0; max-width: 640px; }
label { display: grid; gap: 0.3rem; font-size: 0.9rem; color: var(--vp-c-text-1); }
.req { font-size: 0.75rem; color: var(--vp-c-text-3); }
input, textarea, select { font: inherit; padding: 0.5rem 0.6rem; border: 1px solid var(--vp-c-divider); border-radius: 6px; background: var(--vp-c-bg-alt); color: var(--vp-c-text-1); }
textarea { resize: vertical; }
.row { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
button { padding: 0.55rem 1.2rem; border-radius: 6px; background: var(--vp-c-brand-1); color: white; font-weight: 600; border: 0; cursor: pointer; }
button:disabled { opacity: 0.6; cursor: default; }
.ok { color: var(--vp-c-green-1); font-size: 0.9rem; }
.err { color: var(--vp-c-danger-1); font-size: 0.9rem; }
.note { font-size: 0.8rem; color: var(--vp-c-text-3); margin: 0; }
  .link { background: none; border: 0; padding: 0; color: inherit; text-decoration: underline; cursor: pointer; font: inherit; }
</style>
