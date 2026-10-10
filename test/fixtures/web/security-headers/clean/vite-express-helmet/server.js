import express from "express";
import helmet from "helmet";

const app = express();
app.use(helmet());
app.use(express.static("dist"));
app.listen(3000);
