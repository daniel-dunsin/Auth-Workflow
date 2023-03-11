require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const { not_found, errorHandler } = require("./middlewares/errors.middleware");
const authRoutes = require("./routes/auth.route");
const app = express();

// middlewares
app.use(express.json());
app.use(cors());
app.use(helmet());

// routes
app.use("/api/auth", authRoutes);

// error handlers
app.all("*", not_found);
app.use(errorHandler);

const port = process.env.PORT || 5000;

mongoose.connect(process.env.MONGOOSE_URI).then(() => {
  console.log("Connected to MongoDB");
  app.listen(port, () => {
    console.log(`Server is listening on port ${port}...`);
  });
});
