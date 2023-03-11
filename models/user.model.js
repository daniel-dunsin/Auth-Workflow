require("dotenv").config();
const { default: mongoose } = require("mongoose");
const jwt = require("jsonwebtoken");

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, "Must provide username"],
    trim: true,
    unique: [true, "User with this username exists"],
  },
  email: {
    type: String,
    match:
      /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/,
    trim: true,
    required: [true, "Must provide email"],
    unique: true,
  },
  password: {
    type: String,
    required: [true, "Must provide password"],
  },
  firstname: {
    type: String,
    default: "",
  },
  mobile: {
    type: String,
    default: "",
  },
  lastname: {
    type: String,
    default: "",
  },
  address: {
    type: String,
    default: "",
  },
  verified: {
    type: Boolean,
    default: false,
  },
});

UserSchema.methods.createJWT = async function () {
  const token = jwt.sign(
    { user_id: this._id, username: this.username },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );

  return token;
};

module.exports = mongoose.model("User", UserSchema);
