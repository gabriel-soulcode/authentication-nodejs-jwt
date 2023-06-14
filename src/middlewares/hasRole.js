const jwt = require("jsonwebtoken");
const User = require("../model/User");

// Possibilidades para role = *, admin, common
function hasRole(role) {
  return async (req, res, next) => {
    const authorization = req.headers.authorization;

    if (!authorization) {
      return res.status(400).json({ message: "Token inválido." });
    }

    const [authType, token] = authorization.split(" ");

    try {
      const secret = process.env.JWT_SECRET;

      const decoded = jwt.verify(token, secret);
      const user = await User.findOne({ where: { id: decoded.id } });

      if (!user) {
        return res.status(401).json({ message: "Acesso negado." });
      }

      const allRolesAllowed = role === "*"; // todos os papéis permitidos
      const hasCorrectRole =
        decoded.role === user.role && decoded.role === role; // papel específico permitido

      if (allRolesAllowed || hasCorrectRole) {
        next(); // Só avança se todos os papéis forem permitidos ou o usuário está acessando com papel correto
        return;
      }

      return res.status(403).json({ message: "Sem autorização necessária." });
    } catch (err) {
      return res.status(403).json({ message: "Acesso negado." });
    }
  };
}

module.exports = hasRole;
