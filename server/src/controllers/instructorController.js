import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// Both fields must be plain strings. This rejects operator objects such as
// {"$ne": null} or {"$regex": "^S"} before they can reach MongoDB.
const instructorLoginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
});

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================

function publicProfile(doc) {
  // A successful login is a "trophy": we deliberately return the sensitive
  // fields so a bypass clearly reveals what it compromised.
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role,
    apiKey: doc.apiKey,
    privateEmail: doc.privateEmail,
    privatePhone: doc.privatePhone
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = instructorLoginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.message });
    }

    // ⚠️ VULNERABLE (NoSQL injection): `username` and `password` are placed
    // directly into the query. Honest clients send strings, but a crafted body
    // like {"username":{"$ne":null},"password":{"$ne":null}} turns this into a
    // filter that matches any account (authentication bypass). With
    // {"password":{"$regex":"^S"}} the success/failure response becomes an
    // oracle for extracting the stored password one character at a time.

    // Look up by username only; the password is never part of the query.
    const instructor = await Instructor.findOne({ username: value.username });

    // Same response for "no such user" and "wrong password", so the response
    // reveals nothing about which one failed.
    if (!instructor || !(await instructor.comparePassword(value.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // ⚠️ VULNERABLE (NoSQL injection): the entire query string is used as the
    // MongoDB filter and full documents (incl. password / apiKey / private
    // contact info) are returned. Examples of what this allows:
    //   ?name=Smith                     -> intended, honest use
    //   ?role[$ne]=instructor           -> operator injection, leaks superadmin
    //   ?username[$regex]=^admin        -> regex enumeration
    //   ?$where=this.password.length>10 -> server-side JavaScript execution

    // Build the filter ourselves from an allowlist of fields. A value is used
    // only if it is a plain string, so operator objects like {"$ne": ...} and
    // top-level keys like $where are silently ignored instead of executed.
    const { name, department, role } = req.query;
    const filter = {};
    if (typeof name === 'string' && name.trim() !== '') {
      // Case-insensitive "contains" match. The input is escaped so regex
      // characters in it are treated as literal text, not as a pattern.
      filter.name = { $regex: escapeRegex(name.trim()), $options: 'i' };
    }
    if (typeof department === 'string' && department.trim() !== '') {
      filter.department = department.trim();
    }
    if (typeof role === 'string' && role.trim() !== '') {
      filter.role = role.trim();
    }

    // Return only public fields, never password / apiKey / private contact info.
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}

// Escape characters that have special meaning in a regular expression.
function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
