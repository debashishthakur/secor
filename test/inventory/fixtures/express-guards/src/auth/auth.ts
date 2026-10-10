import { expressjwt as jwt } from "express-jwt";
const auth = {
  required: jwt({ secret: process.env.JWT_SECRET!, algorithms: ["HS256"] }),
  optional: jwt({ secret: process.env.JWT_SECRET!, algorithms: ["HS256"], credentialsRequired: false }),
};
export default auth;
