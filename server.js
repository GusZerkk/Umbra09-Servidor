// UMBRA-09 — Servidor da ficha eletrônica (IRIS COMPANY)
// -----------------------------------------------------
// As fichas ficam guardadas no Supabase (banco de dados gratuito e
// permanente), não em arquivos locais — assim os dados sobrevivem
// mesmo quando o servidor "dorme" e acorda de novo no Render.
// A senha nunca é guardada em texto puro — ela é criptografada com
// bcrypt antes de salvar.

const express = require("express");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3001;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

app.use(cors());
app.use(express.json());

function normalizeKeyword(kw) {
  return kw.toLowerCase().trim();
}

// -- rotas da API ------------------------------------------------------

// Tenta localizar uma ficha existente com palavra-chave + senha
app.post("/api/localizar", async (req, res) => {
  const { keyword, password } = req.body || {};
  if (!keyword || !password) {
    return res.status(400).json({ ok: false, erro: "Preencha palavra-chave e senha." });
  }
  const { data, error } = await supabase
    .from("fichas")
    .select("password_hash, sheet")
    .eq("keyword", normalizeKeyword(keyword))
    .maybeSingle();

  if (error) return res.status(500).json({ ok: false, erro: "Erro ao consultar o arquivo." });
  if (!data) return res.status(404).json({ ok: false, erro: "Arquivo não encontrado." });

  const senhaOk = await bcrypt.compare(password, data.password_hash);
  if (!senhaOk) return res.status(401).json({ ok: false, erro: "Senha incorreta. Acesso negado." });

  return res.json({ ok: true, sheet: data.sheet });
});

// Cria uma nova ficha — recusa se a palavra-chave já existir
app.post("/api/criar", async (req, res) => {
  const { keyword, password, sheet } = req.body || {};
  if (!keyword || !password) {
    return res.status(400).json({ ok: false, erro: "Preencha palavra-chave e senha para o novo registro." });
  }
  const kw = normalizeKeyword(keyword);

  const { data: existing } = await supabase.from("fichas").select("keyword").eq("keyword", kw).maybeSingle();
  if (existing) {
    return res.status(409).json({
      ok: false,
      erro: "Acesso negado: tal indivíduo já possui uma ficha virtual e é impossível de ser recriado sem a exclusão da ficha já feita.",
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const { error } = await supabase.from("fichas").insert({ keyword: kw, password_hash: passwordHash, sheet: sheet || {} });
  if (error) return res.status(500).json({ ok: false, erro: "Erro ao registrar a ficha." });

  return res.json({ ok: true, sheet: sheet || {} });
});

// Salva (sobrescreve) os dados de uma ficha já autenticada
app.post("/api/salvar", async (req, res) => {
  const { keyword, password, sheet } = req.body || {};
  if (!keyword || !password || !sheet) {
    return res.status(400).json({ ok: false, erro: "Dados incompletos." });
  }
  const kw = normalizeKeyword(keyword);

  const { data, error } = await supabase.from("fichas").select("password_hash").eq("keyword", kw).maybeSingle();
  if (error) return res.status(500).json({ ok: false, erro: "Erro ao consultar o arquivo." });
  if (!data) return res.status(404).json({ ok: false, erro: "Arquivo não encontrado." });

  const senhaOk = await bcrypt.compare(password, data.password_hash);
  if (!senhaOk) return res.status(401).json({ ok: false, erro: "Senha incorreta. Acesso negado." });

  const { error: updateError } = await supabase.from("fichas").update({ sheet }).eq("keyword", kw);
  if (updateError) return res.status(500).json({ ok: false, erro: "Erro ao salvar." });

  return res.json({ ok: true });
});

// -- serve o site (frontend) já publicado junto do servidor ------------
const path = require("path");
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Servidor UMBRA-09 rodando na porta ${PORT}`);
});

