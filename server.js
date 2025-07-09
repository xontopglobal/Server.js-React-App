    
// === server/index.js ===
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const authRoutes = require("./routes/auth");
const movieRoutes = require("./routes/movies");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

app.use("/api/auth", authRoutes);
app.use("/api/movies", movieRoutes);

app.listen(5000, () => console.log("Server running on port 5000"));


// === server/models/User.js ===
const mongoose = require("mongoose");
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  favorites: [Object],
});
module.exports = mongoose.model("User", userSchema);


// === server/routes/auth.js ===
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const router = express.Router();

router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword });
  await user.save();
  res.status(201).json({ message: "User registered" });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

module.exports = router;


// === server/routes/movies.js ===
const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const router = express.Router();

router.get("/favorites", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(userId);
    res.json(user.favorites);
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
});

router.post("/favorites", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(userId);
    user.favorites.push(req.body.movie);
    await user.save();
    res.status(201).json({ message: "Movie saved" });
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
});

module.exports = router;
