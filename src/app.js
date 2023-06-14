// Configuração das variáveis de ambiente
const dotenv = require("dotenv");
dotenv.config();

// Outras dependências importantes
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Configurações do banco de dados
const connection = require("./database/database");
const User = require("./model/User");
connection.authenticate();

// Configurações do app express
const express = require("express");
const app = express();
const hasRole = require("./middlewares/hasRole");

app.use(express.json());

// Rotas

// Rota aberta
app.get("/", (req, res) => {
  return res.status(200).json({ message: "Bem-vindo!" });
});

// Rota aberta
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) {
    return res.status(400).json({ message: "O nome é obrigatório." });
  }
  if (!email) {
    return res.status(400).json({ message: "O e-mail é obrigatório." });
  }
  if (!password) {
    return res.status(400).json({ message: "A senha é obrigatória." });
  }

  try {
    const userExists = await User.findOne({ where: { email } });

    if (userExists) {
      return res
        .status(400)
        .json({ message: "Este e-mail já está sendo utilizado." });
    }

    // O valor 12 se refere a um custo computacional no momento de gerar o hash,
    // quanto maior o valor mais iterações serão necessárias para gerar o hash, porém
    // mais seguro será. 2¹² iterações neste caso.
    const passwordHash = await bcrypt.hash(password, 12);

    await User.create({
      name,
      email,
      password: passwordHash,
    });

    return res.status(201).json({ message: "Usuário cadastrado com sucesso." });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Erro interno no servidor.", error });
  }
});

// Rota aberta
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.status(400).json({ message: "O e-mail é obrigatório." });
  }
  if (!password) {
    return res.status(400).json({ message: "A senha é obrigatória." });
  }

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ message: "E-mail não cadastrado." });
    }

    const isSamePassword = bcrypt.compareSync(password, user.password);

    if (isSamePassword) {
      const payload = { id: user.id, email: user.email, role: user.role };
      const secret = process.env.JWT_SECRET;
      const token = jwt.sign(payload, secret, { expiresIn: "7d" });
      return res.status(200).json({ authType: "Bearer", token });
    }

    return res.status(401).json({ message: "Senha inválida." });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Erro interno no servidor.", error });
  }
});

// Rota fechada, apenas admin pode acessar
app.get("/users", hasRole("admin"), async (req, res) => {
  const users = await User.findAll({ attributes: { exclude: ["password"] } });
  res.json(users);
});

app.get("/users/:id", hasRole("admin"), async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findOne({
      where: { id },
      attributes: { exclude: ["password"] },
    });
    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado!" });
    }
    return res.status(200).json(user);
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Erro interno no servidor.", error });
  }
});

// Escuta do servidor
app.listen(8080, async () => {
  console.log("Server running in port 8080.");
  await connection.sync({ force: true });

  // Usuário admin de testes
  const userExists = await User.findOne({
    where: { email: process.env.ADMIN_EMAIL },
  });

  if (!userExists) {
    const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);

    await User.create({
      name: "Admin Default",
      email: process.env.ADMIN_EMAIL,
      password: passwordHash,
      role: "admin",
    });
  }
});
