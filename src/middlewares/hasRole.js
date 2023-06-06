const jwt = require("jsonwebtoken");
const User = require("../model/User");

function hasRole(role) {
    return async (req, res, next) => {
        const authorization = req.headers.authorization;
        if (!authorization) {
            return res.status(401).json({ message: "Token inválido." });
        }

        const [authType, token] = authorization.split(" ");
        try {
            const secret = process.env.JWT_SECRET;
            jwt.verify(token, secret, async (err, decoded) => {
                if (err) {
                    return res.status(403).json({ message: "Acesso negado." });
                }

                const user = await User.findOne({ where: { id: decoded.id } });

                if (!user) {
                    return res.status(403).json({ message: "E-mail não cadastrado." });
                }

                if (role === "*") {
                    next();
                    return;
                }

                if (decoded.role === user.role && decoded.role === role) {
                    next();
                    return;
                }
                
                return res.status(403).json({ message: "Acesso negado." });
            });
        }
        catch (err) {
            return res.status(500).json({ message: "Algo deu errado." });
        }
    }
}

module.exports = hasRole;