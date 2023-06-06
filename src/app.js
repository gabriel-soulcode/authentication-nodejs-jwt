const dotenv = require("dotenv");
const connection = require("./database/database");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

dotenv.config();

const User = require("./model/User");
const hasRole = require("./middlewares/hasRole");

const app = express();

app.use(express.json());

connection.authenticate().then(() => {
    console.log("Connection established");
}).catch((err) => {
    console.log("Error connecting to database");
});

app.get("/", (req, res) => {
    return res.status(200).json({message: "Bem-vindo!"});
});

app.post("/auth/register", async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;
    if(!name) {
        return res.status(400).json({ message: "O nome é obrigatório." });
    }
    if(!email) {
        return res.status(400).json({ message: "O e-mail é obrigatório." });
    }
    if(!password) {
        return res.status(400).json({ message: "A senha é obrigatória." });
    }
    if(!confirmpassword) {
        return res.status(400).json({ message: "A confirmação da senha é obrigatória." });
    }
    if(password != confirmpassword) {
        return res.status(400).json({ message: "As senhas não conferem." });
    }
    try {
        const userExists = await User.findOne({ where: { email } });
        if(userExists) {
            return res.status(400).json({ message: "Este e-mail já está sendo utilizado." });
        }
        const salt = await bcrypt.genSalt(12);
        const passwordHash = await bcrypt.hash(password, salt);
        const user = await User.create({ name, email, password: passwordHash, role: "common" });
        return res.status(201).json({ message: "Usuário cadastrado com sucesso.", user });
    }
    catch(error) {
        return res.status(500).json({ message: "Erro interno no servidor.", error });
    }
});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;
    if(!email) {
        return res.status(400).json({ message: "O e-mail é obrigatório." });
    }
    if(!password) {
        return res.status(400).json({ message: "A senha é obrigatória." });
    }
    try {
        const user = await User.findOne({ where: { email } });
        if(!user) {
            return res.status(404).json({ message: "E-mail não cadastrado." });
        }
        bcrypt.compare(password, user.password, (err, checkPassword) => {
            if(checkPassword) {
                const payload = { id: user.id, email: user.email, role: user.role };
                const secret = process.env.JWT_SECRET;
                const token = jwt.sign(payload, secret, { expiresIn: "7d" });
                return res.status(200).json({ authType: "Bearer", token });
            }
            return res.status(400).json({ message: "Senha inválida." });
        });
        
    }
    catch(error) {
        return res.status(500).json({ message: "Erro interno no servidor.", error });
    }

});

app.get("/user/:id", hasRole("*"), async (req, res) => {
    const { id } = req.params;
    try {
        const user = await User.findOne({ where: { id }, attributes: { exclude: ['password'] } });
        if(!user) {
            return res.status(404).json({ message: "E-mail não cadastrado." });
        }
        return res.status(200).json(user);
    }
    catch(error) {
        return res.status(500).json({ message: "Erro interno no servidor.", error });
    }
});

app.listen(8080, async () => {
    console.log("Server running in port 8080.");
    await connection.sync({ force: true });
});