const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const passportLocalMongoose = require('passport-local-mongoose');

const UserSchema = new Schema({
    username: {
        type: String,
        min: 3,
        max: 255,
        required: true,
    },
    password: {
        min: 8,
        max: 25,
        type: String,
    },
    email: {
        type: String,
        unique: true,
        required: true
    },
    lastLogin: {
        ip: { type: String },
        browser: { type: String },
        os: { type: String },
        device: { type: String },
        location: {
            country: { type: String },
            city: { type: String }
        },
        timestamp: { type: Date }
    },
    registration: {
        ip: { type: String },
        browser: { type: String },
        os: { type: String },
        device: { type: String },
        location: {
            country: { type: String },
            city: { type: String }
        },
        timestamp: { type: Date }
    }
});

UserSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model('User', UserSchema);
