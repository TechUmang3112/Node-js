const jwt = require("jsonwebtoken");

exports.identifier = (res, req, next) => {
  let token;
  if (req.headers.client === "not-browser") {
    token = req.headers.authorization;
  } else {
    token = req.cookies["Authorization"];
  }

  if (!token) {
    return res.status(403).json({ success: false, message: "unauthorized!!" });
  }

  try {
    const userToken = tokrn.split(" ")[1];
    const jwtVerified = jwt.verify(userToken, process.env.TOKEN_SECRET);
    if (jwtVerified) {
      req.user = jwtVerified;
      next();
    } else {
      throw new Error("error in the token");
    }
  } catch (error) {
    console.log(error);
  }
};
