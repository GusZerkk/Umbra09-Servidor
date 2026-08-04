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

// Cria uma nova afiliação e gera um código único — o mestre cria uma senha própria, sem precisar de ficha
app.post("/api/afiliacao/criar", async (req, res) => {
  const { name, quote, bannerUrl, masterKeyword, masterPassword } = req.body || {};
  if (!name || !name.trim()) {
    return res.status(400).json({ ok: false, erro: "Informe um nome para a afiliação." });
  }
  if (!masterKeyword || !masterPassword) {
    return res.status(400).json({ ok: false, erro: "Crie uma palavra-chave e uma senha para ser o mestre desta afiliação." });
  }
  const mkw = normalizeKeyword(masterKeyword);

  let code;
  for (let tries = 0; tries < 6; tries++) {
    code = randomCode();
    const { data } = await supabase.from("afiliacoes").select("code").eq("code", code).maybeSingle();
    if (!data) break;
  }
  const masterPasswordHash = await bcrypt.hash(masterPassword, 10);
  const { error } = await supabase
    .from("afiliacoes")
    .insert({ code, name: name.trim(), quote: quote || "", banner_url: bannerUrl || "", master_keyword: mkw, master_password_hash: masterPasswordHash });
  if (error) return res.status(500).json({ ok: false, erro: "Erro ao criar a afiliação." });
  return res.json({ ok: true, code, name: name.trim(), quote: quote || "", bannerUrl: bannerUrl || "" });
});

// Mostra o mural público de uma afiliação (nome, foto e função de cada membro) + histórico de rolagens
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

  const { data: rolagens } = await supabase
    .from("rolagens")
    .select("*")
    .eq("afiliacao_code", code)
    .order("created_at", { ascending: false })
    .limit(40);

  return res.json({ ok: true, code: afil.code, name: afil.name, quote: afil.quote, bannerUrl: afil.banner_url, membros: lista, rolagens: rolagens || [] });
});

// Confere se quem está pedindo é o mestre da afiliação e devolve as fichas completas dos membros
app.post("/api/afiliacao/mestre", async (req, res) => {
  const { code, masterKeyword, masterPassword } = req.body || {};
  if (!code || !masterKeyword || !masterPassword) return res.status(400).json({ ok: false, erro: "Dados incompletos." });
  const codeNorm = code.toUpperCase().trim();
  const mkw = normalizeKeyword(masterKeyword);

  const { data: afil } = await supabase.from("afiliacoes").select("master_keyword, master_password_hash").eq("code", codeNorm).maybeSingle();
  if (!afil || afil.master_keyword !== mkw) return res.status(403).json({ ok: false, erro: "Você não é o mestre desta afiliação." });

  const senhaOk = await bcrypt.compare(masterPassword, afil.master_password_hash);
  if (!senhaOk) return res.status(401).json({ ok: false, erro: "Senha incorreta." });

  const { data: membros } = await supabase.from("fichas").select("keyword, sheet").eq("afiliacao_code", codeNorm);
  return res.json({ ok: true, membros: membros || [] });
});

// Apaga uma afiliação em definitivo (e desconecta as fichas ligadas a ela)
app.post("/api/afiliacao/deletar", async (req, res) => {
  const { code, masterKeyword, masterPassword } = req.body || {};
  if (!code || !masterKeyword || !masterPassword) return res.status(400).json({ ok: false, erro: "Dados incompletos." });
  const codeNorm = code.toUpperCase().trim();
  const mkw = normalizeKeyword(masterKeyword);

  const { data: afil } = await supabase.from("afiliacoes").select("master_keyword, master_password_hash").eq("code", codeNorm).maybeSingle();
  if (!afil || afil.master_keyword !== mkw) return res.status(403).json({ ok: false, erro: "Você não é o mestre desta afiliação." });

  const senhaOk = await bcrypt.compare(masterPassword, afil.master_password_hash);
  if (!senhaOk) return res.status(401).json({ ok: false, erro: "Senha incorreta." });

  await supabase.from("fichas").update({ afiliacao_code: null }).eq("afiliacao_code", codeNorm);
  await supabase.from("rolagens").delete().eq("afiliacao_code", codeNorm);
  const { error: delErr } = await supabase.from("afiliacoes").delete().eq("code", codeNorm);
  if (delErr) return res.status(500).json({ ok: false, erro: "Erro ao destruir a afiliação." });

  return res.json({ ok: true });
});

// Registra o resultado de uma rolagem no histórico público da afiliação
app.post("/api/afiliacao/rolagem", async (req, res) => {
  const { code, charName, attrLabel, skillName, dado, attrVal, skillVal, total } = req.body || {};
  if (!code) return res.status(400).json({ ok: false });
  await supabase.from("rolagens").insert({
    afiliacao_code: code.toUpperCase().trim(),
    char_name: charName || "Desconhecido",
    attr_label: attrLabel || "",
    skill_name: skillName || "",
    dado: dado || 0,
    attr_val: attrVal || 0,
    skill_val: skillVal || 0,
    total: total || 0,
  });
  return res.json({ ok: true });
});

// -- trilha sonora --------------------------------------------------------

function extractYouTubeId(input) {
  if (!input) return null;
  const trimmed = input.trim();
  if (/^[a-zA-Z0-9_-]{11}$/.test(trimmed)) return trimmed;
  const m = trimmed.match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|shorts\/))([a-zA-Z0-9_-]{11})/);
  return m ? m[1] : null;
}

// Painel do mestre: define a música tocando, se está tocando, e o volume geral
app.post("/api/afiliacao/musica", async (req, res) => {
  const { code, masterKeyword, masterPassword, videoUrl, playing, volume } = req.body || {};
  if (!code || !masterKeyword || !masterPassword) return res.status(400).json({ ok: false, erro: "Dados incompletos." });
  const codeNorm = code.toUpperCase().trim();
  const mkw = normalizeKeyword(masterKeyword);

  const { data: afil } = await supabase.from("afiliacoes").select("master_keyword, master_password_hash").eq("code", codeNorm).maybeSingle();
  if (!afil || afil.master_keyword !== mkw) return res.status(403).json({ ok: false, erro: "Você não é o mestre desta afiliação." });
  const senhaOk = await bcrypt.compare(masterPassword, afil.master_password_hash);
  if (!senhaOk) return res.status(401).json({ ok: false, erro: "Senha incorreta." });

  const update = {};
  if (videoUrl !== undefined && videoUrl !== "") {
    const vid = extractYouTubeId(videoUrl);
    if (!vid) return res.status(400).json({ ok: false, erro: "Link do YouTube inválido." });
    update.music_video_id = vid;
  }
  if (playing !== undefined) update.music_playing = !!playing;
  if (volume !== undefined) update.music_volume = Math.max(0, Math.min(100, Number(volume) || 0));

  const { error } = await supabase.from("afiliacoes").update(update).eq("code", codeNorm);
  if (error) return res.status(500).json({ ok: false, erro: "Erro ao atualizar a trilha sonora." });
  return res.json({ ok: true });
});

// Consulta leve pra tocadores acompanharem o estado da trilha sonora (sem senha)
app.get("/api/afiliacao/:code/musica", async (req, res) => {
  const code = req.params.code.toUpperCase().trim();
  const { data } = await supabase.from("afiliacoes").select("music_video_id, music_playing, music_volume").eq("code", code).maybeSingle();
  if (!data) return res.status(404).json({ ok: false });
  return res.json({ ok: true, videoId: data.music_video_id, playing: data.music_playing, volume: data.music_volume });
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

const nodemailer = require("nodemailer");

let transporter = null;
function getTransporter() {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
    });
  }
  return transporter;
}

async function sendEmail(to, subject, text) {
  const t = getTransporter();
  if (!t) return { ok: false, erro: "E-mail não configurado no servidor." };
  try {
    await t.sendMail({ from: `"IRIS COMPANY" <${process.env.GMAIL_USER}>`, to, subject, text });
    return { ok: true };
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
