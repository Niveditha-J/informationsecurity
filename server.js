const express = require("express");
const cookieParser = require("cookie-parser");
const { JsonDB, Config } = require("node-json-db");
const qrcode = require("qrcode");
const { authenticator } = require("otplib");

const userDb = new JsonDB(new Config("users", true, true, "/"));

const app = express();
app.use(cookieParser());
app.use(express.static("public"));

// login user — only accepts existing users and validates password
app.get("/login", async (req, res) => {
  try {
    const { id, password, code } = req.query;

    // Check if user exists
    let user;
    try {
      user = await userDb.getData("/" + id);
    } catch {
      // User not found
      return res.status(401).send({ error: "Invalid credentials" });
    }

    // Validate password
    if (user.password !== password) {
      return res.status(401).send({ error: "Invalid credentials" });
    }

    // If 2FA enabled, check code
    if (user["2FA"].enabled) {
      if (!code) {
        return res.send({ codeRequested: true }); // ask for 2FA code
      }

      const verified = authenticator.check(code, user["2FA"].secret);
      if (!verified) {
        return res.status(401).send({ error: "Invalid 2FA code" });
      }
    }

    // Set cookie and login success
    return res.cookie("id", id, { httpOnly: true }).send({ success: true });
  } catch (e) {
    return res.status(500).send({ error: "Something went wrong" });
  }
});

// generate QR Image
app.get("/qrImage", async (req, res) => {
  try {
    const { id } = req.cookies;
    if (!id) throw new Error("No user logged in");

    let user = await userDb.getData("/" + id);
    
    if (!user["2FA"]) {
      user["2FA"] = { enabled: false, secret: null, tempSecret: null };
    }

    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(id, "2FA Tutorial", secret);
    const image = await qrcode.toDataURL(uri);

    // Save tempSecret properly
    await userDb.push(`/${id}/2FA/tempSecret`, secret, true);

    return res.send({ success: true, image });
  } catch (error) {
    console.error(error);
    return res.status(500).send({ success: false, error: error.message });
  }
});

// set 2FA
app.get("/set2FA", async (req, res) => {
  try {
    const { id } = req.cookies;
    const { code } = req.query;
    if (!id) throw new Error("No user logged in");

    const user = await userDb.getData("/" + id);
    const { tempSecret } = user["2FA"];

    const verified = authenticator.check(code, tempSecret);
    if (!verified) throw false;

    user["2FA"] = {
      enabled: true,
      secret: tempSecret,
    };

    await userDb.save();

    return res.send({ success: true });
  } catch {
    return res.status(500).send({ success: false });
  }
});

// check session
app.get("/check", (req, res) => {
  const { id } = req.cookies;
  if (id) return res.send({ success: true, id });
  return res.status(500).send({ success: false });
});

// logout user
app.get("/logout", (req, res) => {
  res.clearCookie("id");
  res.send({ success: true });
});

app.listen(3000, () => {
  console.log("App listening on port 3000");
});
