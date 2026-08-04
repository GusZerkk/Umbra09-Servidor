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

  const { error: updateError } = await supabase
    .from("fichas")
    .update({ sheet, afiliacao_code: sheet.afiliacaoCode || null, recovery_email: (sheet.recoveryEmail || "").toLowerCase().trim() || null })
    .eq("keyword", kw);
  if (updateError) return res.status(500).json({ ok: false, erro: "Erro ao salvar." });

  return res.json({ ok: true });
});

// -- afiliações (campanhas) --------------------------------------------

function randomCode(len = 6) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

// Cria uma nova afiliação e gera um código único
app.post("/api/afiliacao/criar", async (req, res) => {
  const { name, quote, bannerUrl } = req.body || {};
  if (!name || !name.trim()) {
    return res.status(400).json({ ok: false, erro: "Informe um nome para a afiliação." });
  }
  let code;
  for (let tries = 0; tries < 6; tries++) {
    code = randomCode();
    const { data } = await supabase.from("afiliacoes").select("code").eq("code", code).maybeSingle();
    if (!data) break;
  }
  const { error } = await supabase.from("afiliacoes").insert({ code, name: name.trim(), quote: quote || "", banner_url: bannerUrl || "" });
  if (error) return res.status(500).json({ ok: false, erro: "Erro ao criar a afiliação." });
  return res.json({ ok: true, code, name: name.trim(), quote: quote || "", bannerUrl: bannerUrl || "" });
});

// Mostra o mural público de uma afiliação (nome, foto e função de cada membro)
app.get("/api/afiliacao/:code", async (req, res) => {
  const code = req.params.code.toUpperCase().trim();
  const { data: afil, error } = await supabase.from("afiliacoes").select("*").eq("code", code).maybeSingle();
  if (error || !afil) return res.status(404).json({ ok: false, erro: "Afiliação não encontrada." });

  const { data: membros } = await supabase.from("fichas").select("sheet, updated_at").eq("afiliacao_code", code);
  const lista = (membros || []).map((m) => ({
    charName: (m.sheet && m.sheet.charName) || "(sem nome)",
    avatarUrl: (m.sheet && m.sheet.avatarUrl) || "",
    funcao: (m.sheet && m.sheet.funcao) || "",
    trajetoria: (m.sheet && m.sheet.trajetoria) || 1,
    updatedAt: m.updated_at,
  }));

  return res.json({ ok: true, code: afil.code, name: afil.name, quote: afil.quote, bannerUrl: afil.banner_url, membros: lista });
});

// Junta uma ficha (autenticada) a uma afiliação existente
app.post("/api/afiliacao/juntar", async (req, res) => {
  const { keyword, password, code } = req.body || {};
  if (!keyword || !password || !code) {
    return res.status(400).json({ ok: false, erro: "Preencha o código da afiliação." });
  }
  const kw = normalizeKeyword(keyword);
  const { data: ficha, error } = await supabase.from("fichas").select("password_hash").eq("keyword", kw).maybeSingle();
  if (error || !ficha) return res.status(404).json({ ok: false, erro: "Arquivo não encontrado." });

  const senhaOk = await bcrypt.compare(password, ficha.password_hash);
  if (!senhaOk) return res.status(401).json({ ok: false, erro: "Senha incorreta. Acesso negado." });

  const codeNorm = code.toUpperCase().trim();
  const { data: afil } = await supabase.from("afiliacoes").select("code, name").eq("code", codeNorm).maybeSingle();
  if (!afil) return res.status(404).json({ ok: false, erro: "Código de afiliação não encontrado." });

  const { error: updErr } = await supabase.from("fichas").update({ afiliacao_code: afil.code }).eq("keyword", kw);
  if (updErr) return res.status(500).json({ ok: false, erro: "Erro ao entrar na afiliação." });

  return res.json({ ok: true, code: afil.code, name: afil.name });
});

// -- recuperação de acesso e exclusão -----------------------------------

async function sendEmail(to, subject, text) {
  if (!process.env.RESEND_API_KEY) return { ok: false, erro: "E-mail não configurado no servidor." };
  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: process.env.RESEND_FROM || "IRIS COMPANY <onboarding@resend.dev>",
        to: [to],
        subject,
        text,
      }),
    });
    return { ok: resp.ok };
  } catch (e) {
    return { ok: false, erro: "Falha ao enviar e-mail." };
  }
}

// Pede a lista de personagens ligados a um e-mail e manda código de redefinição pra cada um
app.post("/api/recuperar", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ ok: false, erro: "Informe um e-mail." });
  const emailNorm = email.toLowerCase().trim();

  const { data: fichas } = await supabase.from("fichas").select("keyword").eq("recovery_email", emailNorm);
  if (fichas && fichas.length) {
    const linhas = [];
    for (const f of fichas) {
      const token = randomCode(8);
      const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();
      await supabase.from("fichas").update({ reset_token: token, reset_token_expires: expires }).eq("keyword", f.keyword);
      linhas.push(`Personagem "${f.keyword}" — código de redefinição: ${token} (válido por 30 minutos)`);
    }
    const texto = `A IRIS COMPANY localizou os seguintes registros conectados a este e-mail:\n\n${linhas.join("\n")}\n\nUse a palavra-chave do personagem junto com o código acima na tela "Redefinir senha" do site para escolher uma senha nova.`;
    await sendEmail(emailNorm, "IRIS COMPANY — Recuperação de acesso", texto);
  }
  // Resposta sempre igual, pra não revelar se o e-mail está ou não cadastrado
  return res.json({ ok: true });
});

// Troca a senha de uma ficha usando o código recebido por e-mail
app.post("/api/redefinir-senha", async (req, res) => {
  const { keyword, token, novaSenha } = req.body || {};
  if (!keyword || !token || !novaSenha) return res.status(400).json({ ok: false, erro: "Preencha todos os campos." });
  const kw = normalizeKeyword(keyword);

  const { data, error } = await supabase.from("fichas").select("reset_token, reset_token_expires").eq("keyword", kw).maybeSingle();
  if (error || !data) return res.status(404).json({ ok: false, erro: "Arquivo não encontrado." });
  if (!data.reset_token || data.reset_token !== token.toUpperCase().trim()) {
    return res.status(401).json({ ok: false, erro: "Código inválido." });
  }
  if (!data.reset_token_expires || new Date(data.reset_token_expires) < new Date()) {
    return res.status(401).json({ ok: false, erro: "Código expirado. Solicite a recuperação novamente." });
  }

  const passwordHash = await bcrypt.hash(novaSenha, 10);
  const { error: updErr } = await supabase.from("fichas").update({ password_hash: passwordHash, reset_token: null, reset_token_expires: null }).eq("keyword", kw);
  if (updErr) return res.status(500).json({ ok: false, erro: "Erro ao redefinir a senha." });

  return res.json({ ok: true });
});

// Apaga uma ficha em definitivo
app.post("/api/deletar", async (req, res) => {
  const { keyword, password } = req.body || {};
  if (!keyword || !password) return res.status(400).json({ ok: false, erro: "Dados incompletos." });
  const kw = normalizeKeyword(keyword);

  const { data, error } = await supabase.from("fichas").select("password_hash").eq("keyword", kw).maybeSingle();
  if (error || !data) return res.status(404).json({ ok: false, erro: "Arquivo não encontrado." });

  const senhaOk = await bcrypt.compare(password, data.password_hash);
  if (!senhaOk) return res.status(401).json({ ok: false, erro: "Senha incorreta. Acesso negado." });

  const { error: delErr } = await supabase.from("fichas").delete().eq("keyword", kw);
  if (delErr) return res.status(500).json({ ok: false, erro: "Erro ao deletar a ficha." });

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
