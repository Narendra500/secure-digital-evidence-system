import jwt from "jsonwebtoken";
import fs from "fs";

const publicKey = fs.readFileSync("../auth-service/public.pem", "utf8");

function authenticate(req, res, next) {

  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: "No token provided" })
  }

  const token = header.split(" ")[1];

  try {

    const decoded = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
    });

    req.user = decoded;

    next();

  } catch (err) {

    return res.status(401).json({ error: "Invalid token" });

  }

}

export default authenticate;