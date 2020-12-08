const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require("bcrypt");
const SALT_ROUNDS = 6;

const userSchema = new Schema({
  name: String,
  email: {
    type: String,
    required: true,
    // Makes it so email field will accept lower or uppercase on email 
    lowercase: true,
    //Doesn't create duplicates
    unique: true
  },
  password: String
}, {
  timestamps: true
});

//Schema to remove password when serializing
userSchema.set('toJSON', {
  transform: function (doc, ret) {
    // remove the password property when serializing doc to JSON
    delete ret.password;
    return ret;
  }
});


// Shcema to hash the user's password
userSchema.pre('save', function (next) {
  const user = this;
  if (!user.isModified('password')) return next();
  // password has been changed - salt and hash it
  bcrypt.hash(user.password, SALT_ROUNDS, function (err, hash) {
    if (err) return next(err);
    // replace the user provided password with the hash
    user.password = hash;
    //runs the next action in the pipeline
    next();
  });
});

userSchema.methods.comparePassword = function (tryPassword, cb) {
  bcrypt.compare(tryPassword, this.password, cb);
};

module.exports = mongoose.model('User', userSchema);